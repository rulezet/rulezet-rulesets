rule TTP_XOR_WriteProcessMemory_0d64 {
  strings:
    $key_0d64 = { 5a 16 [2] 68 34 [2] 6e 01 [2] 40 01 [2] 7f 1d }

  condition:
    any of them
}