rule TTP_XOR_WriteProcessMemory_c64e {
  strings:
    $key_c64e = { 91 3c [2] a3 1e [2] a5 2b [2] 8b 2b [2] b4 37 }

  condition:
    any of them
}