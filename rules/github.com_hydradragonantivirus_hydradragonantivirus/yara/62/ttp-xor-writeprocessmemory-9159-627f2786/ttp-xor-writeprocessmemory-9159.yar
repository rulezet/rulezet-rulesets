rule TTP_XOR_WriteProcessMemory_9159 {
  strings:
    $key_9159 = { c6 2b [2] f4 09 [2] f2 3c [2] dc 3c [2] e3 20 }

  condition:
    any of them
}