rule TTP_XOR_WriteProcessMemory_d04e {
  strings:
    $key_d04e = { 87 3c [2] b5 1e [2] b3 2b [2] 9d 2b [2] a2 37 }

  condition:
    any of them
}