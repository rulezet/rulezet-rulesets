rule TTP_XOR_WriteProcessMemory_6634 {
  strings:
    $key_6634 = { 31 46 [2] 03 64 [2] 05 51 [2] 2b 51 [2] 14 4d }

  condition:
    any of them
}