rule TTP_XOR_WriteProcessMemory_6101 {
  strings:
    $key_6101 = { 36 73 [2] 04 51 [2] 02 64 [2] 2c 64 [2] 13 78 }

  condition:
    any of them
}