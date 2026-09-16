rule TTP_XOR_WriteProcessMemory_d72f {
  strings:
    $key_d72f = { 80 5d [2] b2 7f [2] b4 4a [2] 9a 4a [2] a5 56 }

  condition:
    any of them
}