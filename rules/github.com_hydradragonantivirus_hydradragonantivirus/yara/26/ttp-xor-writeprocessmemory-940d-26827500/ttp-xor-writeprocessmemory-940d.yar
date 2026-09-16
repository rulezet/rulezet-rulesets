rule TTP_XOR_WriteProcessMemory_940d {
  strings:
    $key_940d = { c3 7f [2] f1 5d [2] f7 68 [2] d9 68 [2] e6 74 }

  condition:
    any of them
}