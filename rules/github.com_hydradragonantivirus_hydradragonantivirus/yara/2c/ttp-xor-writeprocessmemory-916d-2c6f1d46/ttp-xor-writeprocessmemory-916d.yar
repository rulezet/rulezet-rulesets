rule TTP_XOR_WriteProcessMemory_916d {
  strings:
    $key_916d = { c6 1f [2] f4 3d [2] f2 08 [2] dc 08 [2] e3 14 }

  condition:
    any of them
}