rule TTP_XOR_WriteProcessMemory_8269 {
  strings:
    $key_8269 = { d5 1b [2] e7 39 [2] e1 0c [2] cf 0c [2] f0 10 }

  condition:
    any of them
}