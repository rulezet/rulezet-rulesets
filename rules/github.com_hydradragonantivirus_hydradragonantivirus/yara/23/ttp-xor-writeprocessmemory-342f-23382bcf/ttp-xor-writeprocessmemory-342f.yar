rule TTP_XOR_WriteProcessMemory_342f {
  strings:
    $key_342f = { 63 5d [2] 51 7f [2] 57 4a [2] 79 4a [2] 46 56 }

  condition:
    any of them
}