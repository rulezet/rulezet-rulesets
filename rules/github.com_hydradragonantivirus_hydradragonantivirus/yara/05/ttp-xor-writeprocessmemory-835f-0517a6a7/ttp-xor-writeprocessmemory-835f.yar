rule TTP_XOR_WriteProcessMemory_835f {
  strings:
    $key_835f = { d4 2d [2] e6 0f [2] e0 3a [2] ce 3a [2] f1 26 }

  condition:
    any of them
}