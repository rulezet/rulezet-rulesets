rule TTP_XOR_WriteProcessMemory_d01e {
  strings:
    $key_d01e = { 87 6c [2] b5 4e [2] b3 7b [2] 9d 7b [2] a2 67 }

  condition:
    any of them
}