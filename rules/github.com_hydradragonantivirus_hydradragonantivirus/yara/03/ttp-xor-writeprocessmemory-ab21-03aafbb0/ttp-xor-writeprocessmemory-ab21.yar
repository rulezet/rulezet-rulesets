rule TTP_XOR_WriteProcessMemory_ab21 {
  strings:
    $key_ab21 = { fc 53 [2] ce 71 [2] c8 44 [2] e6 44 [2] d9 58 }

  condition:
    any of them
}