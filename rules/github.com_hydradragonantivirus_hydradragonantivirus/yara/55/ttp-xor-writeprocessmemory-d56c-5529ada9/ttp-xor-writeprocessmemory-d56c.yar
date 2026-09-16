rule TTP_XOR_WriteProcessMemory_d56c {
  strings:
    $key_d56c = { 82 1e [2] b0 3c [2] b6 09 [2] 98 09 [2] a7 15 }

  condition:
    any of them
}