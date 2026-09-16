rule TTP_XOR_WriteProcessMemory_2f64 {
  strings:
    $key_2f64 = { 78 16 [2] 4a 34 [2] 4c 01 [2] 62 01 [2] 5d 1d }

  condition:
    any of them
}