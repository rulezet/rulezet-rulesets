rule TTP_XOR_WriteProcessMemory_b534 {
  strings:
    $key_b534 = { e2 46 [2] d0 64 [2] d6 51 [2] f8 51 [2] c7 4d }

  condition:
    any of them
}