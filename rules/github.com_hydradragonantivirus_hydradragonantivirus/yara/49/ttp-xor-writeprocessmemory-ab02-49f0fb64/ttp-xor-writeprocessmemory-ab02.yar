rule TTP_XOR_WriteProcessMemory_ab02 {
  strings:
    $key_ab02 = { fc 70 [2] ce 52 [2] c8 67 [2] e6 67 [2] d9 7b }

  condition:
    any of them
}