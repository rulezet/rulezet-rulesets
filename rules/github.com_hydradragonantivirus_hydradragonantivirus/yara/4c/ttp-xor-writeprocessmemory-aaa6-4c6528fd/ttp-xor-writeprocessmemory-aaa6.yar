rule TTP_XOR_WriteProcessMemory_aaa6 {
  strings:
    $key_aaa6 = { fd d4 [2] cf f6 [2] c9 c3 [2] e7 c3 [2] d8 df }

  condition:
    any of them
}