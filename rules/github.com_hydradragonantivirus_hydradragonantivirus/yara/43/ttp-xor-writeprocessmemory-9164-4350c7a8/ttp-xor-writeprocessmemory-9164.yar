rule TTP_XOR_WriteProcessMemory_9164 {
  strings:
    $key_9164 = { c6 16 [2] f4 34 [2] f2 01 [2] dc 01 [2] e3 1d }

  condition:
    any of them
}