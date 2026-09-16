rule TTP_XOR_WriteProcessMemory_ab10 {
  strings:
    $key_ab10 = { fc 62 [2] ce 40 [2] c8 75 [2] e6 75 [2] d9 69 }

  condition:
    any of them
}