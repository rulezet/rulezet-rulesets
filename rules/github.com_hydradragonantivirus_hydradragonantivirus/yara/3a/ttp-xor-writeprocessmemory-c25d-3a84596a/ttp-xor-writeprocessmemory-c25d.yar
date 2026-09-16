rule TTP_XOR_WriteProcessMemory_c25d {
  strings:
    $key_c25d = { 95 2f [2] a7 0d [2] a1 38 [2] 8f 38 [2] b0 24 }

  condition:
    any of them
}