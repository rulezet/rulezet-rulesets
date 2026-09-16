rule TTP_XOR_WriteProcessMemory_2376 {
  strings:
    $key_2376 = { 74 04 [2] 46 26 [2] 40 13 [2] 6e 13 [2] 51 0f }

  condition:
    any of them
}