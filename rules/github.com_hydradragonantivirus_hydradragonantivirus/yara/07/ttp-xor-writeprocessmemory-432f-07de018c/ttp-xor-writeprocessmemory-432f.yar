rule TTP_XOR_WriteProcessMemory_432f {
  strings:
    $key_432f = { 14 5d [2] 26 7f [2] 20 4a [2] 0e 4a [2] 31 56 }

  condition:
    any of them
}