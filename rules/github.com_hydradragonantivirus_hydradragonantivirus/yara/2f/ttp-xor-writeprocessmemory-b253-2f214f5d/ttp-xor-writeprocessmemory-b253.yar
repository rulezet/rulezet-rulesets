rule TTP_XOR_WriteProcessMemory_b253 {
  strings:
    $key_b253 = { e5 21 [2] d7 03 [2] d1 36 [2] ff 36 [2] c0 2a }

  condition:
    any of them
}