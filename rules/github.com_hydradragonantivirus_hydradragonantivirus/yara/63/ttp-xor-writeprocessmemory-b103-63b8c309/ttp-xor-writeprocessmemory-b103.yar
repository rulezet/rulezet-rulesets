rule TTP_XOR_WriteProcessMemory_b103 {
  strings:
    $key_b103 = { e6 71 [2] d4 53 [2] d2 66 [2] fc 66 [2] c3 7a }

  condition:
    any of them
}