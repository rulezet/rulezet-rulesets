rule TTP_XOR_WriteProcessMemory_d02e {
  strings:
    $key_d02e = { 87 5c [2] b5 7e [2] b3 4b [2] 9d 4b [2] a2 57 }

  condition:
    any of them
}