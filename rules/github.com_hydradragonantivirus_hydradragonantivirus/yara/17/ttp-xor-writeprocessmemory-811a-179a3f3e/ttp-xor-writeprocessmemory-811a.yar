rule TTP_XOR_WriteProcessMemory_811a {
  strings:
    $key_811a = { d6 68 [2] e4 4a [2] e2 7f [2] cc 7f [2] f3 63 }

  condition:
    any of them
}