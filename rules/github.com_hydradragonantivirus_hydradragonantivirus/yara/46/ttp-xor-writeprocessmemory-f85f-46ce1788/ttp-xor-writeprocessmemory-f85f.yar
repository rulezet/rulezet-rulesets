rule TTP_XOR_WriteProcessMemory_f85f {
  strings:
    $key_f85f = { af 2d [2] 9d 0f [2] 9b 3a [2] b5 3a [2] 8a 26 }

  condition:
    any of them
}