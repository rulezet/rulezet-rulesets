rule TTP_XOR_WriteProcessMemory_aa94 {
  strings:
    $key_aa94 = { fd e6 [2] cf c4 [2] c9 f1 [2] e7 f1 [2] d8 ed }

  condition:
    any of them
}