rule win_njrat_2 {

    meta:
        author      = "Johannes Bader @viql"
        version     = "v1.0"
        tlp         = "TLP:WHITE"
        date        = "2021-10-01"
        description = "identifies njRat vesrion 0.7 Golden"

    strings:
        $a = "Njrat 0.7 Golden By Hassan Amiri" wide

    condition:
        uint16(0) == 0x5A4D and 
        all of them
}