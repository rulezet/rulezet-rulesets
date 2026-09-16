rule TTP_XOR_WriteProcessMemory_aba2 {
  strings:
    $key_aba2 = { fc d0 [2] ce f2 [2] c8 c7 [2] e6 c7 [2] d9 db }

  condition:
    any of them
}