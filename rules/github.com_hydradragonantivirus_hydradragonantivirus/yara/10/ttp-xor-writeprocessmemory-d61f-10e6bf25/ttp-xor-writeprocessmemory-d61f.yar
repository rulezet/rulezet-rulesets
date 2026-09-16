rule TTP_XOR_WriteProcessMemory_d61f {
  strings:
    $key_d61f = { 81 6d [2] b3 4f [2] b5 7a [2] 9b 7a [2] a4 66 }

  condition:
    any of them
}