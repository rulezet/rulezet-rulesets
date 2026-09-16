rule TTP_XOR_WriteProcessMemory_870a {
  strings:
    $key_870a = { d0 78 [2] e2 5a [2] e4 6f [2] ca 6f [2] f5 73 }

  condition:
    any of them
}