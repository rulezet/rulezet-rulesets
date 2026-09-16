rule TTP_XOR_WriteProcessMemory_924f {
  strings:
    $key_924f = { c5 3d [2] f7 1f [2] f1 2a [2] df 2a [2] e0 36 }

  condition:
    any of them
}