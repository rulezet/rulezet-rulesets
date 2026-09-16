rule isLNK
{
    meta:
        id = "1XKPrHhGUVGxZ9ZtveVhF9"
        fingerprint = "399c994f697568637efb30910b80f5ae7bedd42bf1cf4188cb74610e46cb23a8"
        version = "1.0"
        creation_date = "2020-01-01"
        first_imported = "2021-12-30"
        last_modified = "2025-11-14"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Private rule identifying shortcut (LNK) files. To be used in conjunction with the other LNK rules below."
        category = "INFO"

    strings:
        $lnk = { 4C 00 00 00 01 14 02 00 }

    condition:
        $lnk at 0
}