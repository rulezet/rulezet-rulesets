rule TTP_XOR_WriteProcessMemory_66f8 {
  strings:
    $key_66f8 = { 31 8a [2] 03 a8 [2] 05 9d [2] 2b 9d [2] 14 81 }

  condition:
    any of them
}