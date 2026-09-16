rule TTP_XOR_WriteProcessMemory_b251 {
  strings:
    $key_b251 = { e5 23 [2] d7 01 [2] d1 34 [2] ff 34 [2] c0 28 }

  condition:
    any of them
}