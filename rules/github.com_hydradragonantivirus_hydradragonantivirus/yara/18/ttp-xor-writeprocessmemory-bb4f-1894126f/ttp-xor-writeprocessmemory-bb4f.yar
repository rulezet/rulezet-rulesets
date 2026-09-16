rule TTP_XOR_WriteProcessMemory_bb4f {
  strings:
    $key_bb4f = { ec 3d [2] de 1f [2] d8 2a [2] f6 2a [2] c9 36 }

  condition:
    any of them
}