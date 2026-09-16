rule TTP_XOR_WriteProcessMemory_9471 {
  strings:
    $key_9471 = { c3 03 [2] f1 21 [2] f7 14 [2] d9 14 [2] e6 08 }

  condition:
    any of them
}