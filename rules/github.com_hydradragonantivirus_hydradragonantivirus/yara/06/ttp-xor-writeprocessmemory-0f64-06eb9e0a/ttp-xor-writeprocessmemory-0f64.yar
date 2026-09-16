rule TTP_XOR_WriteProcessMemory_0f64 {
  strings:
    $key_0f64 = { 58 16 [2] 6a 34 [2] 6c 01 [2] 42 01 [2] 7d 1d }

  condition:
    any of them
}