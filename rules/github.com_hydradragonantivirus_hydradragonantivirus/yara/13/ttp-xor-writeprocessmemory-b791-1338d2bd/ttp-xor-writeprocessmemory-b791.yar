rule TTP_XOR_WriteProcessMemory_b791 {
  strings:
    $key_b791 = { e0 e3 [2] d2 c1 [2] d4 f4 [2] fa f4 [2] c5 e8 }

  condition:
    any of them
}