rule TTP_XOR_WriteProcessMemory_9458 {
  strings:
    $key_9458 = { c3 2a [2] f1 08 [2] f7 3d [2] d9 3d [2] e6 21 }

  condition:
    any of them
}