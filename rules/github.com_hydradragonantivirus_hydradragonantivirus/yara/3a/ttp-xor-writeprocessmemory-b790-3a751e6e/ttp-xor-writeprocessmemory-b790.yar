rule TTP_XOR_WriteProcessMemory_b790 {
  strings:
    $key_b790 = { e0 e2 [2] d2 c0 [2] d4 f5 [2] fa f5 [2] c5 e9 }

  condition:
    any of them
}