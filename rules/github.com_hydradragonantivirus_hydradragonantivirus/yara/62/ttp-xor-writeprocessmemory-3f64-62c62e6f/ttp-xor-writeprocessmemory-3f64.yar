rule TTP_XOR_WriteProcessMemory_3f64 {
  strings:
    $key_3f64 = { 68 16 [2] 5a 34 [2] 5c 01 [2] 72 01 [2] 4d 1d }

  condition:
    any of them
}