rule TTP_XOR_WriteProcessMemory_aba0 {
  strings:
    $key_aba0 = { fc d2 [2] ce f0 [2] c8 c5 [2] e6 c5 [2] d9 d9 }

  condition:
    any of them
}