rule TTP_XOR_WriteProcessMemory_d35c {
  strings:
    $key_d35c = { 84 2e [2] b6 0c [2] b0 39 [2] 9e 39 [2] a1 25 }

  condition:
    any of them
}