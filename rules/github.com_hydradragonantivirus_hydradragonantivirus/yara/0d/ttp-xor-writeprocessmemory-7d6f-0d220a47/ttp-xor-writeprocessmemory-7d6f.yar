rule TTP_XOR_WriteProcessMemory_7d6f {
  strings:
    $key_7d6f = { 2a 1d [2] 18 3f [2] 1e 0a [2] 30 0a [2] 0f 16 }

  condition:
    any of them
}