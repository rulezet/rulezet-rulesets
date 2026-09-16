rule TTP_XOR_WriteProcessMemory_0177 {
  strings:
    $key_0177 = { 56 05 [2] 64 27 [2] 62 12 [2] 4c 12 [2] 73 0e }

  condition:
    any of them
}