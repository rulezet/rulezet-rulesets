rule TTP_XOR_WriteProcessMemory_c72a {
  strings:
    $key_c72a = { 90 58 [2] a2 7a [2] a4 4f [2] 8a 4f [2] b5 53 }

  condition:
    any of them
}