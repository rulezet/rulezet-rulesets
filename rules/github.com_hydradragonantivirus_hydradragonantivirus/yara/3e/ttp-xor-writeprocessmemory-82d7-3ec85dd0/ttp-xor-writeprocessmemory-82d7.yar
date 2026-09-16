rule TTP_XOR_WriteProcessMemory_82d7 {
  strings:
    $key_82d7 = { d5 a5 [2] e7 87 [2] e1 b2 [2] cf b2 [2] f0 ae }

  condition:
    any of them
}