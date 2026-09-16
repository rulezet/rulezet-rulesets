rule TTP_XOR_WriteProcessMemory_aa90 {
  strings:
    $key_aa90 = { fd e2 [2] cf c0 [2] c9 f5 [2] e7 f5 [2] d8 e9 }

  condition:
    any of them
}