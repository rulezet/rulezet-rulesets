rule TTP_XOR_WriteProcessMemory_d13a {
  strings:
    $key_d13a = { 86 48 [2] b4 6a [2] b2 5f [2] 9c 5f [2] a3 43 }

  condition:
    any of them
}