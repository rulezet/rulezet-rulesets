rule TTP_XOR_WriteProcessMemory_aaa5 {
  strings:
    $key_aaa5 = { fd d7 [2] cf f5 [2] c9 c0 [2] e7 c0 [2] d8 dc }

  condition:
    any of them
}