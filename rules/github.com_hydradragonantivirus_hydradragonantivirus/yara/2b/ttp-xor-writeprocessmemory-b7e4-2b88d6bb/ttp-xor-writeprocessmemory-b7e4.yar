rule TTP_XOR_WriteProcessMemory_b7e4 {
  strings:
    $key_b7e4 = { e0 96 [2] d2 b4 [2] d4 81 [2] fa 81 [2] c5 9d }

  condition:
    any of them
}