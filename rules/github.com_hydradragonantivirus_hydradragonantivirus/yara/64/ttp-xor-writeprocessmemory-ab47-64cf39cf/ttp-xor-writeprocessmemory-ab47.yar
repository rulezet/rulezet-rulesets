rule TTP_XOR_WriteProcessMemory_ab47 {
  strings:
    $key_ab47 = { fc 35 [2] ce 17 [2] c8 22 [2] e6 22 [2] d9 3e }

  condition:
    any of them
}