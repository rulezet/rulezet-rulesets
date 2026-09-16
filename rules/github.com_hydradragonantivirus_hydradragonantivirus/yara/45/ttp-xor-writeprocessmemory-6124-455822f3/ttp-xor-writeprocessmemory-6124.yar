rule TTP_XOR_WriteProcessMemory_6124 {
  strings:
    $key_6124 = { 36 56 [2] 04 74 [2] 02 41 [2] 2c 41 [2] 13 5d }

  condition:
    any of them
}