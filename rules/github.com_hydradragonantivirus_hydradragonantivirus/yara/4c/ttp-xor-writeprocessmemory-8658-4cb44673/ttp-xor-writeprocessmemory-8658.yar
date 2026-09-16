rule TTP_XOR_WriteProcessMemory_8658 {
  strings:
    $key_8658 = { d1 2a [2] e3 08 [2] e5 3d [2] cb 3d [2] f4 21 }

  condition:
    any of them
}