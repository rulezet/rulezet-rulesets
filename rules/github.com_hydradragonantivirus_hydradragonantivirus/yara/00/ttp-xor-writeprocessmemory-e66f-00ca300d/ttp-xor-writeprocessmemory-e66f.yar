rule TTP_XOR_WriteProcessMemory_e66f {
  strings:
    $key_e66f = { b1 1d [2] 83 3f [2] 85 0a [2] ab 0a [2] 94 16 }

  condition:
    any of them
}