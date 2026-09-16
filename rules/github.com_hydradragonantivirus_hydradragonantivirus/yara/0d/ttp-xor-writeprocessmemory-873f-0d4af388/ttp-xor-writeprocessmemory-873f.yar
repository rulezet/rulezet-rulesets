rule TTP_XOR_WriteProcessMemory_873f {
  strings:
    $key_873f = { d0 4d [2] e2 6f [2] e4 5a [2] ca 5a [2] f5 46 }

  condition:
    any of them
}