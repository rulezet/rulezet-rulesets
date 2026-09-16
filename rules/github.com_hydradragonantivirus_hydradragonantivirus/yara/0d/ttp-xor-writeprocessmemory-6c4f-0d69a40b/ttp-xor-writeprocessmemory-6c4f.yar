rule TTP_XOR_WriteProcessMemory_6c4f {
  strings:
    $key_6c4f = { 3b 3d [2] 09 1f [2] 0f 2a [2] 21 2a [2] 1e 36 }

  condition:
    any of them
}