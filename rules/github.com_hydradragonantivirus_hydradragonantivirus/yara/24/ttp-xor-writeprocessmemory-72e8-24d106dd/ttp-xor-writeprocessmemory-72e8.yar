rule TTP_XOR_WriteProcessMemory_72e8 {
  strings:
    $key_72e8 = { 25 9a [2] 17 b8 [2] 11 8d [2] 3f 8d [2] 00 91 }

  condition:
    any of them
}