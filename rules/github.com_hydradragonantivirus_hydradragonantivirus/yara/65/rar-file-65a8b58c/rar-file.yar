rule rar_file
{
  strings:
    $rar = { 52 61 72 21 1A 07 00 }
    $rar5 = { 52 61 72 21 1A 07 01 00 }
  condition:
    ($rar at 0) or ($rar5 at 0)
}