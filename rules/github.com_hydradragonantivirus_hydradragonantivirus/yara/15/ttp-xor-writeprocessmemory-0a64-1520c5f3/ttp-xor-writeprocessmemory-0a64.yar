rule TTP_XOR_WriteProcessMemory_0a64 {
  strings:
    $key_0a64 = { 5d 16 [2] 6f 34 [2] 69 01 [2] 47 01 [2] 78 1d }

  condition:
    any of them
}