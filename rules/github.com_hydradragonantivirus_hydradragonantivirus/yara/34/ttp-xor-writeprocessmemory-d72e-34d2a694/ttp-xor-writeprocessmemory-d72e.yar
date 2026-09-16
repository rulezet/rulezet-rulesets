rule TTP_XOR_WriteProcessMemory_d72e {
  strings:
    $key_d72e = { 80 5c [2] b2 7e [2] b4 4b [2] 9a 4b [2] a5 57 }

  condition:
    any of them
}