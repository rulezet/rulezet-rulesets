rule TTP_XOR_WriteProcessMemory_16b4 {
  strings:
    $key_16b4 = { 41 c6 [2] 73 e4 [2] 75 d1 [2] 5b d1 [2] 64 cd }

  condition:
    any of them
}