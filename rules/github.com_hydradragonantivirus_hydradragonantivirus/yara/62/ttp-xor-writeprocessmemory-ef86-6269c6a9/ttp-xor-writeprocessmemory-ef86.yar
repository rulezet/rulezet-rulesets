rule TTP_XOR_WriteProcessMemory_ef86 {
  strings:
    $key_ef86 = { b8 f4 [2] 8a d6 [2] 8c e3 [2] a2 e3 [2] 9d ff }

  condition:
    any of them
}