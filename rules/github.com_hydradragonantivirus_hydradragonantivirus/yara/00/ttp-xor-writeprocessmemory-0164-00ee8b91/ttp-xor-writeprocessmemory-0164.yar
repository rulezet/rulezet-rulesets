rule TTP_XOR_WriteProcessMemory_0164 {
  strings:
    $key_0164 = { 56 16 [2] 64 34 [2] 62 01 [2] 4c 01 [2] 73 1d }

  condition:
    any of them
}