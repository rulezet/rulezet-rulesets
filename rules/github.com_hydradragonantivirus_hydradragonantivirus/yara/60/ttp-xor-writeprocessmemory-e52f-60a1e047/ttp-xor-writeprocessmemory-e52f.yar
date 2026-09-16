rule TTP_XOR_WriteProcessMemory_e52f {
  strings:
    $key_e52f = { b2 5d [2] 80 7f [2] 86 4a [2] a8 4a [2] 97 56 }

  condition:
    any of them
}