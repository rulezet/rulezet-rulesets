rule TTP_XOR_WriteProcessMemory_054f {
  strings:
    $key_054f = { 52 3d [2] 60 1f [2] 66 2a [2] 48 2a [2] 77 36 }

  condition:
    any of them
}