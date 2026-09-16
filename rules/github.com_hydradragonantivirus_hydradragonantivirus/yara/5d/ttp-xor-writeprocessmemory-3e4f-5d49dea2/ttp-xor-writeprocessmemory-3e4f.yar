rule TTP_XOR_WriteProcessMemory_3e4f {
  strings:
    $key_3e4f = { 69 3d [2] 5b 1f [2] 5d 2a [2] 73 2a [2] 4c 36 }

  condition:
    any of them
}