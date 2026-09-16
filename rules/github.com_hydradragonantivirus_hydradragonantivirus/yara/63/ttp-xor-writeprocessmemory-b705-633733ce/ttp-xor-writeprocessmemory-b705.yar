rule TTP_XOR_WriteProcessMemory_b705 {
  strings:
    $key_b705 = { e0 77 [2] d2 55 [2] d4 60 [2] fa 60 [2] c5 7c }

  condition:
    any of them
}