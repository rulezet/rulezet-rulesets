rule TTP_XOR_WriteProcessMemory_23b5 {
  strings:
    $key_23b5 = { 74 c7 [2] 46 e5 [2] 40 d0 [2] 6e d0 [2] 51 cc }

  condition:
    any of them
}