rule TTP_XOR_WriteProcessMemory_c03a {
  strings:
    $key_c03a = { 97 48 [2] a5 6a [2] a3 5f [2] 8d 5f [2] b2 43 }

  condition:
    any of them
}