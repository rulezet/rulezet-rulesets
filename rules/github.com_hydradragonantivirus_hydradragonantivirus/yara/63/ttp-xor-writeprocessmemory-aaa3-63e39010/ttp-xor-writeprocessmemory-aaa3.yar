rule TTP_XOR_WriteProcessMemory_aaa3 {
  strings:
    $key_aaa3 = { fd d1 [2] cf f3 [2] c9 c6 [2] e7 c6 [2] d8 da }

  condition:
    any of them
}