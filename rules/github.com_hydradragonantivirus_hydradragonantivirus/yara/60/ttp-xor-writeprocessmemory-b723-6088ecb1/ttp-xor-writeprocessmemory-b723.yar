rule TTP_XOR_WriteProcessMemory_b723 {
  strings:
    $key_b723 = { e0 51 [2] d2 73 [2] d4 46 [2] fa 46 [2] c5 5a }

  condition:
    any of them
}