rule TTP_XOR_WriteProcessMemory_97fe {
  strings:
    $key_97fe = { c0 8c [2] f2 ae [2] f4 9b [2] da 9b [2] e5 87 }

  condition:
    any of them
}