rule TTP_XOR_WriteProcessMemory_34e8 {
  strings:
    $key_34e8 = { 63 9a [2] 51 b8 [2] 57 8d [2] 79 8d [2] 46 91 }

  condition:
    any of them
}