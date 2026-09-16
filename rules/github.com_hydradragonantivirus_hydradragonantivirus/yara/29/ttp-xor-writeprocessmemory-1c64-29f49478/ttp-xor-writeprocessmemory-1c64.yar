rule TTP_XOR_WriteProcessMemory_1c64 {
  strings:
    $key_1c64 = { 4b 16 [2] 79 34 [2] 7f 01 [2] 51 01 [2] 6e 1d }

  condition:
    any of them
}