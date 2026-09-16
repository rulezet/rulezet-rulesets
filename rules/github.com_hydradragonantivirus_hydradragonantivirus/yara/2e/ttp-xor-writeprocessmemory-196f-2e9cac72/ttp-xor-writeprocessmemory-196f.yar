rule TTP_XOR_WriteProcessMemory_196f {
  strings:
    $key_196f = { 4e 1d [2] 7c 3f [2] 7a 0a [2] 54 0a [2] 6b 16 }

  condition:
    any of them
}