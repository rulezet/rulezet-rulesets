rule TTP_XOR_WriteProcessMemory_550f {
  strings:
    $key_550f = { 02 7d [2] 30 5f [2] 36 6a [2] 18 6a [2] 27 76 }

  condition:
    any of them
}