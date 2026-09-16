rule TTP_XOR_WriteProcessMemory_c01d {
  strings:
    $key_c01d = { 97 6f [2] a5 4d [2] a3 78 [2] 8d 78 [2] b2 64 }

  condition:
    any of them
}