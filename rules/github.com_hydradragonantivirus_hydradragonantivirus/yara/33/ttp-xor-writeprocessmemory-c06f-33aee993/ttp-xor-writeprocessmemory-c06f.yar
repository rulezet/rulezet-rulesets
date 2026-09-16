rule TTP_XOR_WriteProcessMemory_c06f {
  strings:
    $key_c06f = { 97 1d [2] a5 3f [2] a3 0a [2] 8d 0a [2] b2 16 }

  condition:
    any of them
}