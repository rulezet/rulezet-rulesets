rule TTP_XOR_WriteProcessMemory_ab39 {
  strings:
    $key_ab39 = { fc 4b [2] ce 69 [2] c8 5c [2] e6 5c [2] d9 40 }

  condition:
    any of them
}