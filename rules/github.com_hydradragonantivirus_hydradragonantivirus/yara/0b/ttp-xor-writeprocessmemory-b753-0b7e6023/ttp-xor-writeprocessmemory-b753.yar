rule TTP_XOR_WriteProcessMemory_b753 {
  strings:
    $key_b753 = { e0 21 [2] d2 03 [2] d4 36 [2] fa 36 [2] c5 2a }

  condition:
    any of them
}