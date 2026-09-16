rule TTP_XOR_WriteProcessMemory_4902 {
  strings:
    $key_4902 = { 1e 70 [2] 2c 52 [2] 2a 67 [2] 04 67 [2] 3b 7b }

  condition:
    any of them
}