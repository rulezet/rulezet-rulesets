rule TTP_XOR_WriteProcessMemory_0f4f {
  strings:
    $key_0f4f = { 58 3d [2] 6a 1f [2] 6c 2a [2] 42 2a [2] 7d 36 }

  condition:
    any of them
}