rule TTP_XOR_WriteProcessMemory_2ed3 {
  strings:
    $key_2ed3 = { 79 a1 [2] 4b 83 [2] 4d b6 [2] 63 b6 [2] 5c aa }

  condition:
    any of them
}