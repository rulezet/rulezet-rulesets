rule TTP_XOR_WriteProcessMemory_aa92 {
  strings:
    $key_aa92 = { fd e0 [2] cf c2 [2] c9 f7 [2] e7 f7 [2] d8 eb }

  condition:
    any of them
}