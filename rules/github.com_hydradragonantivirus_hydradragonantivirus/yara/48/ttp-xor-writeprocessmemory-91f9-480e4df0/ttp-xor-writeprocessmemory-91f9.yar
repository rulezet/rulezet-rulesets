rule TTP_XOR_WriteProcessMemory_91f9 {
  strings:
    $key_91f9 = { c6 8b [2] f4 a9 [2] f2 9c [2] dc 9c [2] e3 80 }

  condition:
    any of them
}