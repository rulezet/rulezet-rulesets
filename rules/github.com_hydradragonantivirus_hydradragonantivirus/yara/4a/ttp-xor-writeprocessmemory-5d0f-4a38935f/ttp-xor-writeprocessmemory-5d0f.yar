rule TTP_XOR_WriteProcessMemory_5d0f {
  strings:
    $key_5d0f = { 0a 7d [2] 38 5f [2] 3e 6a [2] 10 6a [2] 2f 76 }

  condition:
    any of them
}