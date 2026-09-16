rule TTP_XOR_WriteProcessMemory_e04f {
  strings:
    $key_e04f = { b7 3d [2] 85 1f [2] 83 2a [2] ad 2a [2] 92 36 }

  condition:
    any of them
}