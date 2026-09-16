rule TTP_XOR_WriteProcessMemory_c77e {
  strings:
    $key_c77e = { 90 0c [2] a2 2e [2] a4 1b [2] 8a 1b [2] b5 07 }

  condition:
    any of them
}