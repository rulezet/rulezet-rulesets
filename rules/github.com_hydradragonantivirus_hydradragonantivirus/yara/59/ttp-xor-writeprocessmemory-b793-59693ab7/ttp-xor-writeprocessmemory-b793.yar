rule TTP_XOR_WriteProcessMemory_b793 {
  strings:
    $key_b793 = { e0 e1 [2] d2 c3 [2] d4 f6 [2] fa f6 [2] c5 ea }

  condition:
    any of them
}