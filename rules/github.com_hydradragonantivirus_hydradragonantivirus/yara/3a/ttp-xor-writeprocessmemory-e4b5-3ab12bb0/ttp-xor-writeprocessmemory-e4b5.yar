rule TTP_XOR_WriteProcessMemory_e4b5 {
  strings:
    $key_e4b5 = { b3 c7 [2] 81 e5 [2] 87 d0 [2] a9 d0 [2] 96 cc }

  condition:
    any of them
}