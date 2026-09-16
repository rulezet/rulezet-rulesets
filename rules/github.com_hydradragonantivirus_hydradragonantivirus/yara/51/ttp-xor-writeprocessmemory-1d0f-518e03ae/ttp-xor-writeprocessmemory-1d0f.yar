rule TTP_XOR_WriteProcessMemory_1d0f {
  strings:
    $key_1d0f = { 4a 7d [2] 78 5f [2] 7e 6a [2] 50 6a [2] 6f 76 }

  condition:
    any of them
}