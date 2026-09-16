rule TTP_XOR_WriteProcessMemory_920d {
  strings:
    $key_920d = { c5 7f [2] f7 5d [2] f1 68 [2] df 68 [2] e0 74 }

  condition:
    any of them
}