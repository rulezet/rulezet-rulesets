rule TTP_XOR_WriteProcessMemory_951b {
  strings:
    $key_951b = { c2 69 [2] f0 4b [2] f6 7e [2] d8 7e [2] e7 62 }

  condition:
    any of them
}