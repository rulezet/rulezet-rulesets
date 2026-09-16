rule TTP_XOR_WriteProcessMemory_b164 {
  strings:
    $key_b164 = { e6 16 [2] d4 34 [2] d2 01 [2] fc 01 [2] c3 1d }

  condition:
    any of them
}