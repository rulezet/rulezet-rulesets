rule TTP_XOR_WriteProcessMemory_cc82 {
  strings:
    $key_cc82 = { 9b f0 [2] a9 d2 [2] af e7 [2] 81 e7 [2] be fb }

  condition:
    any of them
}