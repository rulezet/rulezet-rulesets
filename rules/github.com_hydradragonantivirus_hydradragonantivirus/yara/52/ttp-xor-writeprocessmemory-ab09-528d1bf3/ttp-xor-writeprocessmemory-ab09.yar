rule TTP_XOR_WriteProcessMemory_ab09 {
  strings:
    $key_ab09 = { fc 7b [2] ce 59 [2] c8 6c [2] e6 6c [2] d9 70 }

  condition:
    any of them
}