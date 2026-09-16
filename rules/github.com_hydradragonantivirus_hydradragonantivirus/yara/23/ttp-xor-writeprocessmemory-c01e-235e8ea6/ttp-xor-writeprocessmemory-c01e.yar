rule TTP_XOR_WriteProcessMemory_c01e {
  strings:
    $key_c01e = { 97 6c [2] a5 4e [2] a3 7b [2] 8d 7b [2] b2 67 }

  condition:
    any of them
}