rule TTP_XOR_WriteProcessMemory_1bd3 {
  strings:
    $key_1bd3 = { 4c a1 [2] 7e 83 [2] 78 b6 [2] 56 b6 [2] 69 aa }

  condition:
    any of them
}