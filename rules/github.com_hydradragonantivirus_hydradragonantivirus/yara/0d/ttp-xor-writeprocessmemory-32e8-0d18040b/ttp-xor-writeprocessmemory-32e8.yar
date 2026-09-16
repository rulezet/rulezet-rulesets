rule TTP_XOR_WriteProcessMemory_32e8 {
  strings:
    $key_32e8 = { 65 9a [2] 57 b8 [2] 51 8d [2] 7f 8d [2] 40 91 }

  condition:
    any of them
}