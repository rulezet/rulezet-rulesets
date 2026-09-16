rule TTP_XOR_WriteProcessMemory_7d0f {
  strings:
    $key_7d0f = { 2a 7d [2] 18 5f [2] 1e 6a [2] 30 6a [2] 0f 76 }

  condition:
    any of them
}