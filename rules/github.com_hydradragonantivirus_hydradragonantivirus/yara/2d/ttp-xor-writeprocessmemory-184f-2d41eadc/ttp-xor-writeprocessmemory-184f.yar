rule TTP_XOR_WriteProcessMemory_184f {
  strings:
    $key_184f = { 4f 3d [2] 7d 1f [2] 7b 2a [2] 55 2a [2] 6a 36 }

  condition:
    any of them
}