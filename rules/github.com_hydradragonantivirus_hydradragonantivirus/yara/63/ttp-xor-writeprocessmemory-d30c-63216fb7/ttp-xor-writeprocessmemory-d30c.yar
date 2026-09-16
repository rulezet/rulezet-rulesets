rule TTP_XOR_WriteProcessMemory_d30c {
  strings:
    $key_d30c = { 84 7e [2] b6 5c [2] b0 69 [2] 9e 69 [2] a1 75 }

  condition:
    any of them
}