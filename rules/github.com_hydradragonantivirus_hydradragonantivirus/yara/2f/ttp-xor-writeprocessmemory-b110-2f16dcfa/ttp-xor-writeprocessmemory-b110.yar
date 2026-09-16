rule TTP_XOR_WriteProcessMemory_b110 {
  strings:
    $key_b110 = { e6 62 [2] d4 40 [2] d2 75 [2] fc 75 [2] c3 69 }

  condition:
    any of them
}