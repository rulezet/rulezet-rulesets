rule TTP_XOR_WriteProcessMemory_b704 {
  strings:
    $key_b704 = { e0 76 [2] d2 54 [2] d4 61 [2] fa 61 [2] c5 7d }

  condition:
    any of them
}