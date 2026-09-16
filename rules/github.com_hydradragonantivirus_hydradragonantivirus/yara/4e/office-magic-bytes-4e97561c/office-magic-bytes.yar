rule office_magic_bytes
{
  strings:
    $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
  condition:
    $magic
}