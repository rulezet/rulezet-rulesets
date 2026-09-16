rule TTP_XOR_WriteProcessMemory_d33c {
  strings:
    $key_d33c = { 84 4e [2] b6 6c [2] b0 59 [2] 9e 59 [2] a1 45 }

  condition:
    any of them
}