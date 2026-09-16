rule TTP_XOR_WriteProcessMemory_16b3 {
  strings:
    $key_16b3 = { 41 c1 [2] 73 e3 [2] 75 d6 [2] 5b d6 [2] 64 ca }

  condition:
    any of them
}