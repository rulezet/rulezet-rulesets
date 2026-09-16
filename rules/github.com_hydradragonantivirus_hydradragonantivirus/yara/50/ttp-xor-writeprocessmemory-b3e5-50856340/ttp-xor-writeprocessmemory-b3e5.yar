rule TTP_XOR_WriteProcessMemory_b3e5 {
  strings:
    $key_b3e5 = { e4 97 [2] d6 b5 [2] d0 80 [2] fe 80 [2] c1 9c }

  condition:
    any of them
}