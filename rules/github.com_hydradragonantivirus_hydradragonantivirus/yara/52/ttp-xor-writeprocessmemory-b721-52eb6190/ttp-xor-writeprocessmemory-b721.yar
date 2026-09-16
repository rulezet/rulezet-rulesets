rule TTP_XOR_WriteProcessMemory_b721 {
  strings:
    $key_b721 = { e0 53 [2] d2 71 [2] d4 44 [2] fa 44 [2] c5 58 }

  condition:
    any of them
}