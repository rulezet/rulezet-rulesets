rule TTP_XOR_WriteProcessMemory_124f {
  strings:
    $key_124f = { 45 3d [2] 77 1f [2] 71 2a [2] 5f 2a [2] 60 36 }

  condition:
    any of them
}