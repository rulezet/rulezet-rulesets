rule TTP_XOR_WriteProcessMemory_c05d {
  strings:
    $key_c05d = { 97 2f [2] a5 0d [2] a3 38 [2] 8d 38 [2] b2 24 }

  condition:
    any of them
}