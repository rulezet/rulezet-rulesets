rule TTP_XOR_WriteProcessMemory_b245 {
  strings:
    $key_b245 = { e5 37 [2] d7 15 [2] d1 20 [2] ff 20 [2] c0 3c }

  condition:
    any of them
}