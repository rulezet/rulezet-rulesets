rule TTP_XOR_WriteProcessMemory_e65f {
  strings:
    $key_e65f = { b1 2d [2] 83 0f [2] 85 3a [2] ab 3a [2] 94 26 }

  condition:
    any of them
}