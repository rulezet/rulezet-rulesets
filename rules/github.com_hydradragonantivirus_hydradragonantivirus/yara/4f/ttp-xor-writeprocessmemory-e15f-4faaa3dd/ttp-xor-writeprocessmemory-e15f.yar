rule TTP_XOR_WriteProcessMemory_e15f {
  strings:
    $key_e15f = { b6 2d [2] 84 0f [2] 82 3a [2] ac 3a [2] 93 26 }

  condition:
    any of them
}