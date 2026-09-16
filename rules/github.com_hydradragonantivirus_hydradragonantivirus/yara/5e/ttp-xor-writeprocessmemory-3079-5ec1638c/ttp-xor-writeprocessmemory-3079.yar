rule TTP_XOR_WriteProcessMemory_3079 {
  strings:
    $key_3079 = { 67 0b [2] 55 29 [2] 53 1c [2] 7d 1c [2] 42 00 }

  condition:
    any of them
}