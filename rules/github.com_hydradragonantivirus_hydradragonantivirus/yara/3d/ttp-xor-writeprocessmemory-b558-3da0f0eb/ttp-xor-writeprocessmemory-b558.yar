rule TTP_XOR_WriteProcessMemory_b558 {
  strings:
    $key_b558 = { e2 2a [2] d0 08 [2] d6 3d [2] f8 3d [2] c7 21 }

  condition:
    any of them
}