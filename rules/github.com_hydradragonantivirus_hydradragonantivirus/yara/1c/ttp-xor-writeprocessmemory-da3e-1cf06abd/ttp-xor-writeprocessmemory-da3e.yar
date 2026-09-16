rule TTP_XOR_WriteProcessMemory_da3e {
  strings:
    $key_da3e = { 8d 4c [2] bf 6e [2] b9 5b [2] 97 5b [2] a8 47 }

  condition:
    any of them
}