rule TTP_XOR_WriteProcessMemory_aba5 {
  strings:
    $key_aba5 = { fc d7 [2] ce f5 [2] c8 c0 [2] e6 c0 [2] d9 dc }

  condition:
    any of them
}