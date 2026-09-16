rule TTP_XOR_WriteProcessMemory_d03e {
  strings:
    $key_d03e = { 87 4c [2] b5 6e [2] b3 5b [2] 9d 5b [2] a2 47 }

  condition:
    any of them
}