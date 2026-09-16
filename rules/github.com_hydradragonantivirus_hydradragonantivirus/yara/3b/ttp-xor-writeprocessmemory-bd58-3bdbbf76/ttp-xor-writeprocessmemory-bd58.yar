rule TTP_XOR_WriteProcessMemory_bd58 {
  strings:
    $key_bd58 = { ea 2a [2] d8 08 [2] de 3d [2] f0 3d [2] cf 21 }

  condition:
    any of them
}