rule TTP_XOR_WriteProcessMemory_16a4 {
  strings:
    $key_16a4 = { 41 d6 [2] 73 f4 [2] 75 c1 [2] 5b c1 [2] 64 dd }

  condition:
    any of them
}