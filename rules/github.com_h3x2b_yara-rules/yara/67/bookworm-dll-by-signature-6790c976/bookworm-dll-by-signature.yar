rule bookworm_dll_by_signature : malware
{
     meta:
         author = "@h3x2b <tracker _AT h3x.eu>"
         description = "Detect bookworm.dll loader"

     strings:
         $a = { 80 34 18 58 }
         $b = { 80 34 18 78 }
         $c = { 80 34 18 D0 }

     condition:
         all of them
}