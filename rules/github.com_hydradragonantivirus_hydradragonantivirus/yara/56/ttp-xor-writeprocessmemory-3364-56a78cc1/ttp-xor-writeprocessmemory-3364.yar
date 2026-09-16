rule TTP_XOR_WriteProcessMemory_3364 {
  strings:
    $key_3364 = { 64 16 [2] 56 34 [2] 50 01 [2] 7e 01 [2] 41 1d }

  condition:
    any of them
}