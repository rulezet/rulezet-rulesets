rule win_phorpiex_b {

    meta:
        author          = "Johannes Bader @viql"
        version         = "v1.0"
        tlp             = "TLP:WHITE"
        date            = "2023-04-24"
        description     = "detects unpacked Phorpiex samples"
        malpedia_family = "win.phorpiex"
        hash_md5        = "0149c897678e3b6f8ed36c10db0802fd"
        hash_sha1       = "6595a05cb9d7e554a2dabe5b8939401dc72a02de"
        hash_sha256     = "f1c8a026f2e1bd19df7c83567e57d236f64a9323ff35ec98b62025223f59aa5c"

    strings:
        $path_1 = "\\public_html" ascii 
        $path_2 = "\\htdocs" ascii
        $path_3 = "\\httpdocs" ascii
        $path_4 = "\\wwwroot" ascii
        $path_5 = "\\ftproot" ascii
        $path_6 = "\\share" ascii
        $path_7 = "\\income" ascii
        $path_8 = "\\upload" ascii

        $pdb = "\\Release\\Trik.pdb" ascii

    condition:
        uint16(0) == 0x5A4D and 
        all of ($path*) and
        $pdb
}