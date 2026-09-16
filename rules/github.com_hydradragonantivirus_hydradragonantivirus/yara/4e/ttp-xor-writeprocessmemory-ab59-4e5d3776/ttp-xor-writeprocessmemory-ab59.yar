rule TTP_XOR_WriteProcessMemory_ab59 {
  strings:
    $key_ab59 = { fc 2b [2] ce 09 [2] c8 3c [2] e6 3c [2] d9 20 }

  condition:
    any of them
}