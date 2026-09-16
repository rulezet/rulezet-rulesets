rule TTP_XOR_WriteProcessMemory_d73f {
  strings:
    $key_d73f = { 80 4d [2] b2 6f [2] b4 5a [2] 9a 5a [2] a5 46 }

  condition:
    any of them
}