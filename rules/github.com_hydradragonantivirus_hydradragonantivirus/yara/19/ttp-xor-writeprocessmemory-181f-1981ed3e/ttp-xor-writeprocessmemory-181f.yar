rule TTP_XOR_WriteProcessMemory_181f {
  strings:
    $key_181f = { 4f 6d [2] 7d 4f [2] 7b 7a [2] 55 7a [2] 6a 66 }

  condition:
    any of them
}