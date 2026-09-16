rule TTP_XOR_WriteProcessMemory_c06c {
  strings:
    $key_c06c = { 97 1e [2] a5 3c [2] a3 09 [2] 8d 09 [2] b2 15 }

  condition:
    any of them
}