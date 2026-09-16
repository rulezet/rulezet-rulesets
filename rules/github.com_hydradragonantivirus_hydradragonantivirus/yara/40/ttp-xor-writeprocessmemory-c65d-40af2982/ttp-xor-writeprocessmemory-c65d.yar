rule TTP_XOR_WriteProcessMemory_c65d {
  strings:
    $key_c65d = { 91 2f [2] a3 0d [2] a5 38 [2] 8b 38 [2] b4 24 }

  condition:
    any of them
}