rule TTP_XOR_WriteProcessMemory_f86f {
  strings:
    $key_f86f = { af 1d [2] 9d 3f [2] 9b 0a [2] b5 0a [2] 8a 16 }

  condition:
    any of them
}