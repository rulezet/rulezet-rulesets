rule TTP_XOR_WriteProcessMemory_0173 {
  strings:
    $key_0173 = { 56 01 [2] 64 23 [2] 62 16 [2] 4c 16 [2] 73 0a }

  condition:
    any of them
}