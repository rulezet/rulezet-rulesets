rule TTP_XOR_WriteProcessMemory_ab13 {
  strings:
    $key_ab13 = { fc 61 [2] ce 43 [2] c8 76 [2] e6 76 [2] d9 6a }

  condition:
    any of them
}