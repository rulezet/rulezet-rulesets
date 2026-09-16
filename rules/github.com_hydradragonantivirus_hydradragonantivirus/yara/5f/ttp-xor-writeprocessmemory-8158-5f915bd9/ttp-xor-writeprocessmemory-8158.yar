rule TTP_XOR_WriteProcessMemory_8158 {
  strings:
    $key_8158 = { d6 2a [2] e4 08 [2] e2 3d [2] cc 3d [2] f3 21 }

  condition:
    any of them
}