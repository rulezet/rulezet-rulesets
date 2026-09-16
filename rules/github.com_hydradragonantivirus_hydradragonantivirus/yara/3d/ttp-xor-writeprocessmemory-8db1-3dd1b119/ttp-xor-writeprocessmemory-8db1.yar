rule TTP_XOR_WriteProcessMemory_8db1 {
  strings:
    $key_8db1 = { da c3 [2] e8 e1 [2] ee d4 [2] c0 d4 [2] ff c8 }

  condition:
    any of them
}