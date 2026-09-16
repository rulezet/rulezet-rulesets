rule TTP_XOR_WriteProcessMemory_584f {
  strings:
    $key_584f = { 0f 3d [2] 3d 1f [2] 3b 2a [2] 15 2a [2] 2a 36 }

  condition:
    any of them
}