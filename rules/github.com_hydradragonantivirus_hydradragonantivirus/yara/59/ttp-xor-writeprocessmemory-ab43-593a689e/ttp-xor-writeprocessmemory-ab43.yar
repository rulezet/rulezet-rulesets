rule TTP_XOR_WriteProcessMemory_ab43 {
  strings:
    $key_ab43 = { fc 31 [2] ce 13 [2] c8 26 [2] e6 26 [2] d9 3a }

  condition:
    any of them
}