rule TTP_XOR_WriteProcessMemory_2976 {
  strings:
    $key_2976 = { 7e 04 [2] 4c 26 [2] 4a 13 [2] 64 13 [2] 5b 0f }

  condition:
    any of them
}