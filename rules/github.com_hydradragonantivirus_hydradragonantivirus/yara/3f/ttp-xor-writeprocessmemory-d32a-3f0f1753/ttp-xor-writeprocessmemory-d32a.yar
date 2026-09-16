rule TTP_XOR_WriteProcessMemory_d32a {
  strings:
    $key_d32a = { 84 58 [2] b6 7a [2] b0 4f [2] 9e 4f [2] a1 53 }

  condition:
    any of them
}