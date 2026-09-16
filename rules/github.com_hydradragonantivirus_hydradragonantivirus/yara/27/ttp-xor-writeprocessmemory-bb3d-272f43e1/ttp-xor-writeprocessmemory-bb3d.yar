rule TTP_XOR_WriteProcessMemory_bb3d {
  strings:
    $key_bb3d = { ec 4f [2] de 6d [2] d8 58 [2] f6 58 [2] c9 44 }

  condition:
    any of them
}