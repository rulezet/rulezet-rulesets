rule TTP_XOR_WriteProcessMemory_947d {
  strings:
    $key_947d = { c3 0f [2] f1 2d [2] f7 18 [2] d9 18 [2] e6 04 }

  condition:
    any of them
}