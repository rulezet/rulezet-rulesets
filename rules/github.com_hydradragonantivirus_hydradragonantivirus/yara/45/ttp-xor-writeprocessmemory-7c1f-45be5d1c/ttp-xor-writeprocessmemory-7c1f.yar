rule TTP_XOR_WriteProcessMemory_7c1f {
  strings:
    $key_7c1f = { 2b 6d [2] 19 4f [2] 1f 7a [2] 31 7a [2] 0e 66 }

  condition:
    any of them
}