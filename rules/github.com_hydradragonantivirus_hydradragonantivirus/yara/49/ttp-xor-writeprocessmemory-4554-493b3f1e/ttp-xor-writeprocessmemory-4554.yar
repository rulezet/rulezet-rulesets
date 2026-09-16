rule TTP_XOR_WriteProcessMemory_4554 {
  strings:
    $key_4554 = { 12 26 [2] 20 04 [2] 26 31 [2] 08 31 [2] 37 2d }

  condition:
    any of them
}