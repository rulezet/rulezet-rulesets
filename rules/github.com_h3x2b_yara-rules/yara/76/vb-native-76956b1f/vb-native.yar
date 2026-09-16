rule vb_native: info compiler vb
{
    meta:
                description = "VisualBasic compiled to Native code, http://waleedassar.blogspot.com/2012/03/visual-basic-malware-part-1.html"

    strings:
        $str_vb_01 = "VB5"
        $str_vb_ncode = { E9 E9 E9 E9 CC CC CC CC CC CC CC CC CC CC CC CC 55 8B EC }

    condition:
        ( $str_vb_01 )
        and $str_vb_ncode
}