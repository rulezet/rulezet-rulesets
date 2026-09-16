rule TTP_XOR_WriteProcessMemory_574f {
  strings:
    $key_574f = { 00 3d [2] 32 1f [2] 34 2a [2] 1a 2a [2] 25 36 }

  condition:
    any of them
}