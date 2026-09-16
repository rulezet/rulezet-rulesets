rule TTP_XOR_WriteProcessMemory_d73a {
  strings:
    $key_d73a = { 80 48 [2] b2 6a [2] b4 5f [2] 9a 5f [2] a5 43 }

  condition:
    any of them
}