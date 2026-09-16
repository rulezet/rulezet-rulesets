rule TTP_XOR_WriteProcessMemory_c74c {
  strings:
    $key_c74c = { 90 3e [2] a2 1c [2] a4 29 [2] 8a 29 [2] b5 35 }

  condition:
    any of them
}