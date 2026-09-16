rule TTP_XOR_WriteProcessMemory_c21a {
  strings:
    $key_c21a = { 95 68 [2] a7 4a [2] a1 7f [2] 8f 7f [2] b0 63 }

  condition:
    any of them
}