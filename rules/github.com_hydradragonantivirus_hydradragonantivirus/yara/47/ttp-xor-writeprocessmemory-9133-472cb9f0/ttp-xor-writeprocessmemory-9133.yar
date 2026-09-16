rule TTP_XOR_WriteProcessMemory_9133 {
  strings:
    $key_9133 = { c6 41 [2] f4 63 [2] f2 56 [2] dc 56 [2] e3 4a }

  condition:
    any of them
}