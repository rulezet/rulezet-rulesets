rule TTP_XOR_WriteProcessMemory_d13c {
  strings:
    $key_d13c = { 86 4e [2] b4 6c [2] b2 59 [2] 9c 59 [2] a3 45 }

  condition:
    any of them
}