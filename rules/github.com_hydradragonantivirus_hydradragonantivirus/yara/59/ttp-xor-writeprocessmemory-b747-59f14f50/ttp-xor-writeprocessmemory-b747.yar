rule TTP_XOR_WriteProcessMemory_b747 {
  strings:
    $key_b747 = { e0 35 [2] d2 17 [2] d4 22 [2] fa 22 [2] c5 3e }

  condition:
    any of them
}