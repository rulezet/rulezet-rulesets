rule INDICATOR_XML_OLE_AutoLoad_Document {
    meta:
        description = "detects AutoLoad documents using OLE Object"
        author = "ditekSHen"
    strings:
        $s1 = "autoLoad=\"true\"" ascii
        $s2 = "/relationships/oleObject\"" ascii
        $s3 = "Target=\"../embeddings/oleObject" ascii
    condition:
        uint32(0) == 0x6d783f3c and all of ($s*)
}