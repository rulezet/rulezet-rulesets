rule TTP_XOR_WriteProcessMemory_d23c {
  strings:
    $key_d23c = { 85 4e [2] b7 6c [2] b1 59 [2] 9f 59 [2] a0 45 }

  condition:
    any of them
}