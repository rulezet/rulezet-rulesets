rule TTP_XOR_WriteProcessMemory_0e26 {
  strings:
    $key_0e26 = { 59 54 [2] 6b 76 [2] 6d 43 [2] 43 43 [2] 7c 5f }

  condition:
    any of them
}