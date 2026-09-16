rule TTP_XOR_WriteProcessMemory_91cb {
  strings:
    $key_91cb = { c6 b9 [2] f4 9b [2] f2 ae [2] dc ae [2] e3 b2 }

  condition:
    any of them
}