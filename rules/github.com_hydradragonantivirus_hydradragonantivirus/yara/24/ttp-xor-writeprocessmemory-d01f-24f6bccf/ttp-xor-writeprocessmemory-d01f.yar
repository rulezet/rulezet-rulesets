rule TTP_XOR_WriteProcessMemory_d01f {
  strings:
    $key_d01f = { 87 6d [2] b5 4f [2] b3 7a [2] 9d 7a [2] a2 66 }

  condition:
    any of them
}