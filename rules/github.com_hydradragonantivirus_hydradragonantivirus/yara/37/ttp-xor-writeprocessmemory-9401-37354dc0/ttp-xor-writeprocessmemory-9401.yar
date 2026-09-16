rule TTP_XOR_WriteProcessMemory_9401 {
  strings:
    $key_9401 = { c3 73 [2] f1 51 [2] f7 64 [2] d9 64 [2] e6 78 }

  condition:
    any of them
}