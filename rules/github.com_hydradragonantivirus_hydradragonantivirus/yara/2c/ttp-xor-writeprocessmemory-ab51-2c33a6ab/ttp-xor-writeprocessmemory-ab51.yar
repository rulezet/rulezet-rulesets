rule TTP_XOR_WriteProcessMemory_ab51 {
  strings:
    $key_ab51 = { fc 23 [2] ce 01 [2] c8 34 [2] e6 34 [2] d9 28 }

  condition:
    any of them
}