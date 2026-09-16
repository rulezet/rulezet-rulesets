rule TTP_XOR_WriteProcessMemory_424f {
  strings:
    $key_424f = { 15 3d [2] 27 1f [2] 21 2a [2] 0f 2a [2] 30 36 }

  condition:
    any of them
}