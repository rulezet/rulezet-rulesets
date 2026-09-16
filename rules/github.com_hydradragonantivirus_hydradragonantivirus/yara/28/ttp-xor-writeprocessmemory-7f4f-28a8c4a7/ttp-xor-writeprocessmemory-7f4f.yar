rule TTP_XOR_WriteProcessMemory_7f4f {
  strings:
    $key_7f4f = { 28 3d [2] 1a 1f [2] 1c 2a [2] 32 2a [2] 0d 36 }

  condition:
    any of them
}