rule TTP_XOR_WriteProcessMemory_870f {
  strings:
    $key_870f = { d0 7d [2] e2 5f [2] e4 6a [2] ca 6a [2] f5 76 }

  condition:
    any of them
}