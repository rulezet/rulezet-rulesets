rule TTP_XOR_WriteProcessMemory_524f {
  strings:
    $key_524f = { 05 3d [2] 37 1f [2] 31 2a [2] 1f 2a [2] 20 36 }

  condition:
    any of them
}