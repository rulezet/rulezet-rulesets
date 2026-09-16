rule TTP_XOR_WriteProcessMemory_b224 {
  strings:
    $key_b224 = { e5 56 [2] d7 74 [2] d1 41 [2] ff 41 [2] c0 5d }

  condition:
    any of them
}