rule TTP_XOR_WriteProcessMemory_866d {
  strings:
    $key_866d = { d1 1f [2] e3 3d [2] e5 08 [2] cb 08 [2] f4 14 }

  condition:
    any of them
}