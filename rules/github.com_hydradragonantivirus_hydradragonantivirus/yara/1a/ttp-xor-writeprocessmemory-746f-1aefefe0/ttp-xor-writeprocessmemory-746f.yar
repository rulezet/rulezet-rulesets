rule TTP_XOR_WriteProcessMemory_746f {
  strings:
    $key_746f = { 23 1d [2] 11 3f [2] 17 0a [2] 39 0a [2] 06 16 }

  condition:
    any of them
}