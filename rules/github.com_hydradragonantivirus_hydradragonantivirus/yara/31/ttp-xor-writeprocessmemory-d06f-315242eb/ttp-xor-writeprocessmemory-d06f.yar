rule TTP_XOR_WriteProcessMemory_d06f {
  strings:
    $key_d06f = { 87 1d [2] b5 3f [2] b3 0a [2] 9d 0a [2] a2 16 }

  condition:
    any of them
}