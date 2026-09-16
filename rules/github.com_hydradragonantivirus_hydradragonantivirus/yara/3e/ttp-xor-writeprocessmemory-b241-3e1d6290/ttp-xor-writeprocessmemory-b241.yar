rule TTP_XOR_WriteProcessMemory_b241 {
  strings:
    $key_b241 = { e5 33 [2] d7 11 [2] d1 24 [2] ff 24 [2] c0 38 }

  condition:
    any of them
}