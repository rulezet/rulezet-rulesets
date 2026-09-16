rule TTP_XOR_WriteProcessMemory_fa4f {
  strings:
    $key_fa4f = { ad 3d [2] 9f 1f [2] 99 2a [2] b7 2a [2] 88 36 }

  condition:
    any of them
}