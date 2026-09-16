rule TTP_XOR_WriteProcessMemory_6f64 {
  strings:
    $key_6f64 = { 38 16 [2] 0a 34 [2] 0c 01 [2] 22 01 [2] 1d 1d }

  condition:
    any of them
}