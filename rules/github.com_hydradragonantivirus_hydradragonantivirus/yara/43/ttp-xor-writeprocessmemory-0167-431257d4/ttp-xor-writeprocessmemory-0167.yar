rule TTP_XOR_WriteProcessMemory_0167 {
  strings:
    $key_0167 = { 56 15 [2] 64 37 [2] 62 02 [2] 4c 02 [2] 73 1e }

  condition:
    any of them
}