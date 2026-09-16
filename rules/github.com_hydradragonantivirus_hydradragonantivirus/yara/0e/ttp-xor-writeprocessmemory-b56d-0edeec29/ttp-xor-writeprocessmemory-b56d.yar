rule TTP_XOR_WriteProcessMemory_b56d {
  strings:
    $key_b56d = { e2 1f [2] d0 3d [2] d6 08 [2] f8 08 [2] c7 14 }

  condition:
    any of them
}