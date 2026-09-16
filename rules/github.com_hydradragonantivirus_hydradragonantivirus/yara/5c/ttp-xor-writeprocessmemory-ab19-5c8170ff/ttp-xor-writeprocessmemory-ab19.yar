rule TTP_XOR_WriteProcessMemory_ab19 {
  strings:
    $key_ab19 = { fc 6b [2] ce 49 [2] c8 7c [2] e6 7c [2] d9 60 }

  condition:
    any of them
}