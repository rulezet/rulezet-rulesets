rule TTP_XOR_WriteProcessMemory_356f {
  strings:
    $key_356f = { 62 1d [2] 50 3f [2] 56 0a [2] 78 0a [2] 47 16 }

  condition:
    any of them
}