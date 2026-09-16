rule TTP_XOR_WriteProcessMemory_523f {
  strings:
    $key_523f = { 05 4d [2] 37 6f [2] 31 5a [2] 1f 5a [2] 20 46 }

  condition:
    any of them
}