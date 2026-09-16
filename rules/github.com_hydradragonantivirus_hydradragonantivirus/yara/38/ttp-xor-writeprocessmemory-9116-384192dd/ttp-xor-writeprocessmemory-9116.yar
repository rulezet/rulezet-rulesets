rule TTP_XOR_WriteProcessMemory_9116 {
  strings:
    $key_9116 = { c6 64 [2] f4 46 [2] f2 73 [2] dc 73 [2] e3 6f }

  condition:
    any of them
}