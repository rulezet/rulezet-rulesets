rule TTP_XOR_WriteProcessMemory_8058 {
  strings:
    $key_8058 = { d7 2a [2] e5 08 [2] e3 3d [2] cd 3d [2] f2 21 }

  condition:
    any of them
}