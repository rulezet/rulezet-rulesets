rule TTP_XOR_WriteProcessMemory_40e8 {
  strings:
    $key_40e8 = { 17 9a [2] 25 b8 [2] 23 8d [2] 0d 8d [2] 32 91 }

  condition:
    any of them
}