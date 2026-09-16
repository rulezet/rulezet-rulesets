rule IsOLE : OLE
{
    meta:
        description = "Identifier for OLE files"
        author = "Seth Hardy"
        last_modified = "2014-05-06"
        
    strings:
        $magic = {d0 cf 11 e0 a1 b1 1a e1}
    
    condition:
        $magic at 0
}