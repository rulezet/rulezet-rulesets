rule TTP_XOR_WriteProcessMemory_6133 {
  strings:
    $key_6133 = { 36 41 [2] 04 63 [2] 02 56 [2] 2c 56 [2] 13 4a }

  condition:
    any of them
}