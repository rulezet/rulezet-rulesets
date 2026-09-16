rule TTP_XOR_WriteProcessMemory_eb5f {
  strings:
    $key_eb5f = { bc 2d [2] 8e 0f [2] 88 3a [2] a6 3a [2] 99 26 }

  condition:
    any of them
}