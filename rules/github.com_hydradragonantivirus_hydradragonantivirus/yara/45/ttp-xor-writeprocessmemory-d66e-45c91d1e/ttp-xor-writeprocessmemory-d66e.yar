rule TTP_XOR_WriteProcessMemory_d66e {
  strings:
    $key_d66e = { 81 1c [2] b3 3e [2] b5 0b [2] 9b 0b [2] a4 17 }

  condition:
    any of them
}