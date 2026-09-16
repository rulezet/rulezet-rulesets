rule TTP_XOR_WriteProcessMemory_2764 {
  strings:
    $key_2764 = { 70 16 [2] 42 34 [2] 44 01 [2] 6a 01 [2] 55 1d }

  condition:
    any of them
}