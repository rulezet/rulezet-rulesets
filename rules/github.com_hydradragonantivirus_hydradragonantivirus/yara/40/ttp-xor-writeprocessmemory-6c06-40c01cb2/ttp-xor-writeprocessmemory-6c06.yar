rule TTP_XOR_WriteProcessMemory_6c06 {
  strings:
    $key_6c06 = { 3b 74 [2] 09 56 [2] 0f 63 [2] 21 63 [2] 1e 7f }

  condition:
    any of them
}