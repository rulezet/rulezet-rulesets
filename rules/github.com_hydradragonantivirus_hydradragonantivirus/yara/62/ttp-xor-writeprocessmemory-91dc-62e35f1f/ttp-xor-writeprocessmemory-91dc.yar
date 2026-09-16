rule TTP_XOR_WriteProcessMemory_91dc {
  strings:
    $key_91dc = { c6 ae [2] f4 8c [2] f2 b9 [2] dc b9 [2] e3 a5 }

  condition:
    any of them
}