rule TTP_XOR_WriteProcessMemory_c65a {
  strings:
    $key_c65a = { 91 28 [2] a3 0a [2] a5 3f [2] 8b 3f [2] b4 23 }

  condition:
    any of them
}