rule TTP_XOR_WriteProcessMemory_ab49 {
  strings:
    $key_ab49 = { fc 3b [2] ce 19 [2] c8 2c [2] e6 2c [2] d9 30 }

  condition:
    any of them
}