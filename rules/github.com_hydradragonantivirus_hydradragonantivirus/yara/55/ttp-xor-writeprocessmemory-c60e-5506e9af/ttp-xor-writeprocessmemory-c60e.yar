rule TTP_XOR_WriteProcessMemory_c60e {
  strings:
    $key_c60e = { 91 7c [2] a3 5e [2] a5 6b [2] 8b 6b [2] b4 77 }

  condition:
    any of them
}