rule TTP_XOR_WriteProcessMemory_832d {
  strings:
    $key_832d = { d4 5f [2] e6 7d [2] e0 48 [2] ce 48 [2] f1 54 }

  condition:
    any of them
}