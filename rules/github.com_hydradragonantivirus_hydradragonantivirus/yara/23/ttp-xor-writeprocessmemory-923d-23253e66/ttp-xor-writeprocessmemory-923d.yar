rule TTP_XOR_WriteProcessMemory_923d {
  strings:
    $key_923d = { c5 4f [2] f7 6d [2] f1 58 [2] df 58 [2] e0 44 }

  condition:
    any of them
}