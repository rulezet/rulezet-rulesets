rule TTP_XOR_WriteProcessMemory_4754 {
  strings:
    $key_4754 = { 10 26 [2] 22 04 [2] 24 31 [2] 0a 31 [2] 35 2d }

  condition:
    any of them
}