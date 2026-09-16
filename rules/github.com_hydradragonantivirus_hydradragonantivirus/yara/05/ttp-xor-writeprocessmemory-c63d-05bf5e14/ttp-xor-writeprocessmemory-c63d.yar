rule TTP_XOR_WriteProcessMemory_c63d {
  strings:
    $key_c63d = { 91 4f [2] a3 6d [2] a5 58 [2] 8b 58 [2] b4 44 }

  condition:
    any of them
}