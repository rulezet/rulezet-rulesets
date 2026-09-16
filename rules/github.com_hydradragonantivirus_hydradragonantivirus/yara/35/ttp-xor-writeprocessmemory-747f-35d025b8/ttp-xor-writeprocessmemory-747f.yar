rule TTP_XOR_WriteProcessMemory_747f {
  strings:
    $key_747f = { 23 0d [2] 11 2f [2] 17 1a [2] 39 1a [2] 06 06 }

  condition:
    any of them
}