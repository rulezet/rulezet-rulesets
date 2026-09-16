rule TTP_XOR_WriteProcessMemory_3729 {
  strings:
    $key_3729 = { 60 5b [2] 52 79 [2] 54 4c [2] 7a 4c [2] 45 50 }

  condition:
    any of them
}