rule TTP_XOR_WriteProcessMemory_d05f {
  strings:
    $key_d05f = { 87 2d [2] b5 0f [2] b3 3a [2] 9d 3a [2] a2 26 }

  condition:
    any of them
}