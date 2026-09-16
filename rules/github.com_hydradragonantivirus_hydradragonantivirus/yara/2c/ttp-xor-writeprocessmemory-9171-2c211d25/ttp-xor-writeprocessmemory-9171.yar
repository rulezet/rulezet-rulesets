rule TTP_XOR_WriteProcessMemory_9171 {
  strings:
    $key_9171 = { c6 03 [2] f4 21 [2] f2 14 [2] dc 14 [2] e3 08 }

  condition:
    any of them
}