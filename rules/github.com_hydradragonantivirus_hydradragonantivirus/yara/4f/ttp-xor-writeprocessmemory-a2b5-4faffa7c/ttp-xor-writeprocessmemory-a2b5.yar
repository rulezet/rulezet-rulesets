rule TTP_XOR_WriteProcessMemory_a2b5 {
  strings:
    $key_a2b5 = { f5 c7 [2] c7 e5 [2] c1 d0 [2] ef d0 [2] d0 cc }

  condition:
    any of them
}