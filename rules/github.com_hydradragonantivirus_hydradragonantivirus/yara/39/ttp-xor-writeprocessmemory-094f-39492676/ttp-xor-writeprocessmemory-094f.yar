rule TTP_XOR_WriteProcessMemory_094f {
  strings:
    $key_094f = { 5e 3d [2] 6c 1f [2] 6a 2a [2] 44 2a [2] 7b 36 }

  condition:
    any of them
}