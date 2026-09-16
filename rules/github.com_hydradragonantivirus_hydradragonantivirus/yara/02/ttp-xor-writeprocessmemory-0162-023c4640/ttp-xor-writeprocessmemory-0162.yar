rule TTP_XOR_WriteProcessMemory_0162 {
  strings:
    $key_0162 = { 56 10 [2] 64 32 [2] 62 07 [2] 4c 07 [2] 73 1b }

  condition:
    any of them
}