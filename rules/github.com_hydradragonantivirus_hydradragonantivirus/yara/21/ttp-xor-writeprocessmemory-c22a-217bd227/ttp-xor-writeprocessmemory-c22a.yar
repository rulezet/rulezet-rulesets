rule TTP_XOR_WriteProcessMemory_c22a {
  strings:
    $key_c22a = { 95 58 [2] a7 7a [2] a1 4f [2] 8f 4f [2] b0 53 }

  condition:
    any of them
}