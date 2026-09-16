rule ComfooCode : Comfoo Family 
{
    meta:
        description = "Comfoo code features"
        author = "Seth Hardy"
        last_modified = "2014-06-20"
        
    strings:
        $resource = { 6A 6C 6A 59 55 E8 01 FA FF FF }
  
    condition:
        any of them
}