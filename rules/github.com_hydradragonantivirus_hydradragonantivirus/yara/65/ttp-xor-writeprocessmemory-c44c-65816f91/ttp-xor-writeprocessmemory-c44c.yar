rule TTP_XOR_WriteProcessMemory_c44c {
  strings:
    $key_c44c = { 93 3e [2] a1 1c [2] a7 29 [2] 89 29 [2] b6 35 }

  condition:
    any of them
}