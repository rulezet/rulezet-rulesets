rule TTP_XOR_WriteProcessMemory_317f {
  strings:
    $key_317f = { 66 0d [2] 54 2f [2] 52 1a [2] 7c 1a [2] 43 06 }

  condition:
    any of them
}