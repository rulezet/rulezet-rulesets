rule TTP_XOR_WriteProcessMemory_0143 {
  strings:
    $key_0143 = { 56 31 [2] 64 13 [2] 62 26 [2] 4c 26 [2] 73 3a }

  condition:
    any of them
}