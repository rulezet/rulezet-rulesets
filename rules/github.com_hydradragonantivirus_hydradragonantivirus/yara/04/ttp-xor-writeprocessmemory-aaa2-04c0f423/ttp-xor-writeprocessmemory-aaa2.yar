rule TTP_XOR_WriteProcessMemory_aaa2 {
  strings:
    $key_aaa2 = { fd d0 [2] cf f2 [2] c9 c7 [2] e7 c7 [2] d8 db }

  condition:
    any of them
}