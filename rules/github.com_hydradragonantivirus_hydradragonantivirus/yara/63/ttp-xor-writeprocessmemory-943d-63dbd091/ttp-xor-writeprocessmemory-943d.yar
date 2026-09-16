rule TTP_XOR_WriteProcessMemory_943d {
  strings:
    $key_943d = { c3 4f [2] f1 6d [2] f7 58 [2] d9 58 [2] e6 44 }

  condition:
    any of them
}