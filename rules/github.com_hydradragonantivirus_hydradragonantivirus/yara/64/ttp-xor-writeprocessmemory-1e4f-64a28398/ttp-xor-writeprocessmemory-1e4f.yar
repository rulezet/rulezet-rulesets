rule TTP_XOR_WriteProcessMemory_1e4f {
  strings:
    $key_1e4f = { 49 3d [2] 7b 1f [2] 7d 2a [2] 53 2a [2] 6c 36 }

  condition:
    any of them
}