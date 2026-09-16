rule TTP_XOR_WriteProcessMemory_b431 {
  strings:
    $key_b431 = { e3 43 [2] d1 61 [2] d7 54 [2] f9 54 [2] c6 48 }

  condition:
    any of them
}