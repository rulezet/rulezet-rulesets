rule TTP_XOR_WriteProcessMemory_92ff {
  strings:
    $key_92ff = { c5 8d [2] f7 af [2] f1 9a [2] df 9a [2] e0 86 }

  condition:
    any of them
}