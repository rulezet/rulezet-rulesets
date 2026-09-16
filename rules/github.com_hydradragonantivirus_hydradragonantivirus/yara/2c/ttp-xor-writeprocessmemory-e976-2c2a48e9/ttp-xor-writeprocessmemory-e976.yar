rule TTP_XOR_WriteProcessMemory_e976 {
  strings:
    $key_e976 = { be 04 [2] 8c 26 [2] 8a 13 [2] a4 13 [2] 9b 0f }

  condition:
    any of them
}