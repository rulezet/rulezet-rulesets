rule TTP_XOR_WriteProcessMemory_62e8 {
  strings:
    $key_62e8 = { 35 9a [2] 07 b8 [2] 01 8d [2] 2f 8d [2] 10 91 }

  condition:
    any of them
}