rule TTP_XOR_WriteProcessMemory_b131 {
  strings:
    $key_b131 = { e6 43 [2] d4 61 [2] d2 54 [2] fc 54 [2] c3 48 }

  condition:
    any of them
}