rule TTP_XOR_WriteProcessMemory_b2e5 {
  strings:
    $key_b2e5 = { e5 97 [2] d7 b5 [2] d1 80 [2] ff 80 [2] c0 9c }

  condition:
    any of them
}