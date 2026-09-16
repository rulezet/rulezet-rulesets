rule TTP_XOR_WriteProcessMemory_7d1f {
  strings:
    $key_7d1f = { 2a 6d [2] 18 4f [2] 1e 7a [2] 30 7a [2] 0f 66 }

  condition:
    any of them
}