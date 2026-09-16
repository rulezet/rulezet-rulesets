rule TTP_XOR_WriteProcessMemory_d04c {
  strings:
    $key_d04c = { 87 3e [2] b5 1c [2] b3 29 [2] 9d 29 [2] a2 35 }

  condition:
    any of them
}