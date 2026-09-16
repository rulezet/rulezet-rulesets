rule TTP_XOR_WriteProcessMemory_d00c {
  strings:
    $key_d00c = { 87 7e [2] b5 5c [2] b3 69 [2] 9d 69 [2] a2 75 }

  condition:
    any of them
}