rule TTP_XOR_WriteProcessMemory_eba0 {
  strings:
    $key_eba0 = { bc d2 [2] 8e f0 [2] 88 c5 [2] a6 c5 [2] 99 d9 }

  condition:
    any of them
}