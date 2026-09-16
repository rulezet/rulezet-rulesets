rule TTP_XOR_WriteProcessMemory_ef4f {
  strings:
    $key_ef4f = { b8 3d [2] 8a 1f [2] 8c 2a [2] a2 2a [2] 9d 36 }

  condition:
    any of them
}