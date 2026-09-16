rule TTP_XOR_WriteProcessMemory_c74d {
  strings:
    $key_c74d = { 90 3f [2] a2 1d [2] a4 28 [2] 8a 28 [2] b5 34 }

  condition:
    any of them
}