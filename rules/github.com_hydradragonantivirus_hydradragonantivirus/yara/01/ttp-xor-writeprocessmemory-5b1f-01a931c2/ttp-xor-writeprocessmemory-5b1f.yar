rule TTP_XOR_WriteProcessMemory_5b1f {
  strings:
    $key_5b1f = { 0c 6d [2] 3e 4f [2] 38 7a [2] 16 7a [2] 29 66 }

  condition:
    any of them
}