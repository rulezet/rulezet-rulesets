rule TTP_XOR_WriteProcessMemory_82dc {
  strings:
    $key_82dc = { d5 ae [2] e7 8c [2] e1 b9 [2] cf b9 [2] f0 a5 }

  condition:
    any of them
}