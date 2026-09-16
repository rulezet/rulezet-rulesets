rule TTP_XOR_WriteProcessMemory_53a4 {
  strings:
    $key_53a4 = { 04 d6 [2] 36 f4 [2] 30 c1 [2] 1e c1 [2] 21 dd }

  condition:
    any of them
}