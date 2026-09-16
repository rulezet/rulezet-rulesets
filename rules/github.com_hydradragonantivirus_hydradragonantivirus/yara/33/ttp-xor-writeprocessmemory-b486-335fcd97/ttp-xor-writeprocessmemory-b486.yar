rule TTP_XOR_WriteProcessMemory_b486 {
  strings:
    $key_b486 = { e3 f4 [2] d1 d6 [2] d7 e3 [2] f9 e3 [2] c6 ff }

  condition:
    any of them
}