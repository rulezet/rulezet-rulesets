rule TTP_XOR_WriteProcessMemory_d06e {
  strings:
    $key_d06e = { 87 1c [2] b5 3e [2] b3 0b [2] 9d 0b [2] a2 17 }

  condition:
    any of them
}