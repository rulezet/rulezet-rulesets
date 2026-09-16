rule TTP_XOR_WriteProcessMemory_754f {
  strings:
    $key_754f = { 22 3d [2] 10 1f [2] 16 2a [2] 38 2a [2] 07 36 }

  condition:
    any of them
}