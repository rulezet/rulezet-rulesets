rule TTP_XOR_WriteProcessMemory_9144 {
  strings:
    $key_9144 = { c6 36 [2] f4 14 [2] f2 21 [2] dc 21 [2] e3 3d }

  condition:
    any of them
}