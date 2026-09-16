rule TTP_XOR_WriteProcessMemory_b250 {
  strings:
    $key_b250 = { e5 22 [2] d7 00 [2] d1 35 [2] ff 35 [2] c0 29 }

  condition:
    any of them
}