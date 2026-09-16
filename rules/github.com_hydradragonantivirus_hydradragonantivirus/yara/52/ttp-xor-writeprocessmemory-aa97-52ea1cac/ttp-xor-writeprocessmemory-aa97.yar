rule TTP_XOR_WriteProcessMemory_aa97 {
  strings:
    $key_aa97 = { fd e5 [2] cf c7 [2] c9 f2 [2] e7 f2 [2] d8 ee }

  condition:
    any of them
}