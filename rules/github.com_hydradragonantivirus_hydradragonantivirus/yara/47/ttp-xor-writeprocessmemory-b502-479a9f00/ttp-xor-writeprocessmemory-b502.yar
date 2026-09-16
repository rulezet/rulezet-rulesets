rule TTP_XOR_WriteProcessMemory_b502 {
  strings:
    $key_b502 = { e2 70 [2] d0 52 [2] d6 67 [2] f8 67 [2] c7 7b }

  condition:
    any of them
}