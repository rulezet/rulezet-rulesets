rule TTP_XOR_WriteProcessMemory_ab31 {
  strings:
    $key_ab31 = { fc 43 [2] ce 61 [2] c8 54 [2] e6 54 [2] d9 48 }

  condition:
    any of them
}