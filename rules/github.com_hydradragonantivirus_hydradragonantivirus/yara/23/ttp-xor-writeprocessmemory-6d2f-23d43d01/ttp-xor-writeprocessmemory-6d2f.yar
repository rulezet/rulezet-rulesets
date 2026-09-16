rule TTP_XOR_WriteProcessMemory_6d2f {
  strings:
    $key_6d2f = { 3a 5d [2] 08 7f [2] 0e 4a [2] 20 4a [2] 1f 56 }

  condition:
    any of them
}