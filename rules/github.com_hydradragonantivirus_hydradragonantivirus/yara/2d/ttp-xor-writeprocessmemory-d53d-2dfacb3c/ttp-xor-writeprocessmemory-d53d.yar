rule TTP_XOR_WriteProcessMemory_d53d {
  strings:
    $key_d53d = { 82 4f [2] b0 6d [2] b6 58 [2] 98 58 [2] a7 44 }

  condition:
    any of them
}