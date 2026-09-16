rule TTP_XOR_WriteProcessMemory_b380 {
  strings:
    $key_b380 = { e4 f2 [2] d6 d0 [2] d0 e5 [2] fe e5 [2] c1 f9 }

  condition:
    any of them
}