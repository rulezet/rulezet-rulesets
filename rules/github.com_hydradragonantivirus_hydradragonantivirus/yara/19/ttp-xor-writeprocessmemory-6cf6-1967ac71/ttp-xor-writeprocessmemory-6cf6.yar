rule TTP_XOR_WriteProcessMemory_6cf6 {
  strings:
    $key_6cf6 = { 3b 84 [2] 09 a6 [2] 0f 93 [2] 21 93 [2] 1e 8f }

  condition:
    any of them
}