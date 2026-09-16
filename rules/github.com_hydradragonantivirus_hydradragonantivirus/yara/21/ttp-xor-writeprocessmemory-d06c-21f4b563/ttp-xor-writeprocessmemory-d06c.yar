rule TTP_XOR_WriteProcessMemory_d06c {
  strings:
    $key_d06c = { 87 1e [2] b5 3c [2] b3 09 [2] 9d 09 [2] a2 15 }

  condition:
    any of them
}