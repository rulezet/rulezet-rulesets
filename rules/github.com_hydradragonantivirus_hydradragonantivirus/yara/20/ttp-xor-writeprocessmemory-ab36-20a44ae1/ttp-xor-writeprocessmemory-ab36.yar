rule TTP_XOR_WriteProcessMemory_ab36 {
  strings:
    $key_ab36 = { fc 44 [2] ce 66 [2] c8 53 [2] e6 53 [2] d9 4f }

  condition:
    any of them
}