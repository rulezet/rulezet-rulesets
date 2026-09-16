rule TTP_XOR_WriteProcessMemory_aa96 {
  strings:
    $key_aa96 = { fd e4 [2] cf c6 [2] c9 f3 [2] e7 f3 [2] d8 ef }

  condition:
    any of them
}