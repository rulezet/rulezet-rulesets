rule TTP_XOR_WriteProcessMemory_b261 {
  strings:
    $key_b261 = { e5 13 [2] d7 31 [2] d1 04 [2] ff 04 [2] c0 18 }

  condition:
    any of them
}