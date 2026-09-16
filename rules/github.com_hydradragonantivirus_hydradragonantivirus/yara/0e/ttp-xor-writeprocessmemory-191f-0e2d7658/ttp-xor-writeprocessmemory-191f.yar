rule TTP_XOR_WriteProcessMemory_191f {
  strings:
    $key_191f = { 4e 6d [2] 7c 4f [2] 7a 7a [2] 54 7a [2] 6b 66 }

  condition:
    any of them
}