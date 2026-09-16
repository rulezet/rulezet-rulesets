rule TTP_XOR_WriteProcessMemory_d21e {
  strings:
    $key_d21e = { 85 6c [2] b7 4e [2] b1 7b [2] 9f 7b [2] a0 67 }

  condition:
    any of them
}