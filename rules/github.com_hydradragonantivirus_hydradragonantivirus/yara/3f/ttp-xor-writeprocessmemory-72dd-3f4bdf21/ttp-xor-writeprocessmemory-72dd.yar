rule TTP_XOR_WriteProcessMemory_72dd {
  strings:
    $key_72dd = { 25 af [2] 17 8d [2] 11 b8 [2] 3f b8 [2] 00 a4 }

  condition:
    any of them
}