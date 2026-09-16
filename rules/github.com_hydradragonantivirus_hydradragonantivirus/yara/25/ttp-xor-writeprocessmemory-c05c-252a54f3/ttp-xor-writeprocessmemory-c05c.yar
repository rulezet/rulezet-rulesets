rule TTP_XOR_WriteProcessMemory_c05c {
  strings:
    $key_c05c = { 97 2e [2] a5 0c [2] a3 39 [2] 8d 39 [2] b2 25 }

  condition:
    any of them
}