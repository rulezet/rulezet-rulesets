rule TTP_XOR_WriteProcessMemory_b701 {
  strings:
    $key_b701 = { e0 73 [2] d2 51 [2] d4 64 [2] fa 64 [2] c5 78 }

  condition:
    any of them
}