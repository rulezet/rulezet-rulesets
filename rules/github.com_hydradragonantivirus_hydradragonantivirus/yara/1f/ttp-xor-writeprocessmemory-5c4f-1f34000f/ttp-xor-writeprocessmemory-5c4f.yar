rule TTP_XOR_WriteProcessMemory_5c4f {
  strings:
    $key_5c4f = { 0b 3d [2] 39 1f [2] 3f 2a [2] 11 2a [2] 2e 36 }

  condition:
    any of them
}