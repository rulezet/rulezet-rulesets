rule TTP_XOR_WriteProcessMemory_d63d {
  strings:
    $key_d63d = { 81 4f [2] b3 6d [2] b5 58 [2] 9b 58 [2] a4 44 }

  condition:
    any of them
}