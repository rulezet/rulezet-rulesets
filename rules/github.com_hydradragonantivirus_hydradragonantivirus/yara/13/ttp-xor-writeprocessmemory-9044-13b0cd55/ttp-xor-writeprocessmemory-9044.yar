rule TTP_XOR_WriteProcessMemory_9044 {
  strings:
    $key_9044 = { c7 36 [2] f5 14 [2] f3 21 [2] dd 21 [2] e2 3d }

  condition:
    any of them
}