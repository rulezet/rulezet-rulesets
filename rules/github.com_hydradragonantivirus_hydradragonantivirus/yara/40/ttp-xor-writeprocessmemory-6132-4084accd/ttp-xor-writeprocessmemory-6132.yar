rule TTP_XOR_WriteProcessMemory_6132 {
  strings:
    $key_6132 = { 36 40 [2] 04 62 [2] 02 57 [2] 2c 57 [2] 13 4b }

  condition:
    any of them
}