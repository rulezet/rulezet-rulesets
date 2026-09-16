rule TTP_XOR_WriteProcessMemory_c72f {
  strings:
    $key_c72f = { 90 5d [2] a2 7f [2] a4 4a [2] 8a 4a [2] b5 56 }

  condition:
    any of them
}