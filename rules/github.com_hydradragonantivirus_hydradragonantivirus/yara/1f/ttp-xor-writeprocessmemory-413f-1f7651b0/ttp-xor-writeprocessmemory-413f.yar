rule TTP_XOR_WriteProcessMemory_413f {
  strings:
    $key_413f = { 16 4d [2] 24 6f [2] 22 5a [2] 0c 5a [2] 33 46 }

  condition:
    any of them
}