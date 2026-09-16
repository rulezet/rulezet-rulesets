rule TTP_XOR_WriteProcessMemory_d36c {
  strings:
    $key_d36c = { 84 1e [2] b6 3c [2] b0 09 [2] 9e 09 [2] a1 15 }

  condition:
    any of them
}