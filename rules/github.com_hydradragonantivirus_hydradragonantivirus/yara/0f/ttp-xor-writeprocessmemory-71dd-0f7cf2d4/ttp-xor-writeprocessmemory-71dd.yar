rule TTP_XOR_WriteProcessMemory_71dd {
  strings:
    $key_71dd = { 26 af [2] 14 8d [2] 12 b8 [2] 3c b8 [2] 03 a4 }

  condition:
    any of them
}