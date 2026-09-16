rule TTP_XOR_WriteProcessMemory_080f {
  strings:
    $key_080f = { 5f 7d [2] 6d 5f [2] 6b 6a [2] 45 6a [2] 7a 76 }

  condition:
    any of them
}