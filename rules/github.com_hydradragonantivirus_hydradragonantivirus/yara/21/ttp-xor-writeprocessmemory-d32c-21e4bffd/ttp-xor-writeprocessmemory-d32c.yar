rule TTP_XOR_WriteProcessMemory_d32c {
  strings:
    $key_d32c = { 84 5e [2] b6 7c [2] b0 49 [2] 9e 49 [2] a1 55 }

  condition:
    any of them
}