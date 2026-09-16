rule TTP_XOR_WriteProcessMemory_3e26 {
  strings:
    $key_3e26 = { 69 54 [2] 5b 76 [2] 5d 43 [2] 73 43 [2] 4c 5f }

  condition:
    any of them
}