rule TTP_XOR_WriteProcessMemory_365f {
  strings:
    $key_365f = { 61 2d [2] 53 0f [2] 55 3a [2] 7b 3a [2] 44 26 }

  condition:
    any of them
}