rule TTP_XOR_WriteProcessMemory_ab29 {
  strings:
    $key_ab29 = { fc 5b [2] ce 79 [2] c8 4c [2] e6 4c [2] d9 50 }

  condition:
    any of them
}