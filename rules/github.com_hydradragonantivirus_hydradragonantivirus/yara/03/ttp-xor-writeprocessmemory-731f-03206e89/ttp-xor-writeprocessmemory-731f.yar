rule TTP_XOR_WriteProcessMemory_731f {
  strings:
    $key_731f = { 24 6d [2] 16 4f [2] 10 7a [2] 3e 7a [2] 01 66 }

  condition:
    any of them
}