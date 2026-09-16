rule TTP_XOR_WriteProcessMemory_3864 {
  strings:
    $key_3864 = { 6f 16 [2] 5d 34 [2] 5b 01 [2] 75 01 [2] 4a 1d }

  condition:
    any of them
}