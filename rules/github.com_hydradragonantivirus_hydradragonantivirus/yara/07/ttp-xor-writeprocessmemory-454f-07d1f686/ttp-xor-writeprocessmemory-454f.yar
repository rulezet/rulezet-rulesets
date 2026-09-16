rule TTP_XOR_WriteProcessMemory_454f {
  strings:
    $key_454f = { 12 3d [2] 20 1f [2] 26 2a [2] 08 2a [2] 37 36 }

  condition:
    any of them
}