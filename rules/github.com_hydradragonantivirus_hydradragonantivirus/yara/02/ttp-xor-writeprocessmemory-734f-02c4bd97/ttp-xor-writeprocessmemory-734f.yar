rule TTP_XOR_WriteProcessMemory_734f {
  strings:
    $key_734f = { 24 3d [2] 16 1f [2] 10 2a [2] 3e 2a [2] 01 36 }

  condition:
    any of them
}