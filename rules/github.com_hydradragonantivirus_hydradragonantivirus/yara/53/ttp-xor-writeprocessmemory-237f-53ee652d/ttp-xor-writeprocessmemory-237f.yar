rule TTP_XOR_WriteProcessMemory_237f {
  strings:
    $key_237f = { 74 0d [2] 46 2f [2] 40 1a [2] 6e 1a [2] 51 06 }

  condition:
    any of them
}