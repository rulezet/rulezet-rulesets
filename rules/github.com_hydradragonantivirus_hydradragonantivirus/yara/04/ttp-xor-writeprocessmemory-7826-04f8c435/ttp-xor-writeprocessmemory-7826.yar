rule TTP_XOR_WriteProcessMemory_7826 {
  strings:
    $key_7826 = { 2f 54 [2] 1d 76 [2] 1b 43 [2] 35 43 [2] 0a 5f }

  condition:
    any of them
}