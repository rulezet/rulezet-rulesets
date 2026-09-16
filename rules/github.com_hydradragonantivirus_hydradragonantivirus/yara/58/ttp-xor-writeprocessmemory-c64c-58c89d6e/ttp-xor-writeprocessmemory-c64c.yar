rule TTP_XOR_WriteProcessMemory_c64c {
  strings:
    $key_c64c = { 91 3e [2] a3 1c [2] a5 29 [2] 8b 29 [2] b4 35 }

  condition:
    any of them
}