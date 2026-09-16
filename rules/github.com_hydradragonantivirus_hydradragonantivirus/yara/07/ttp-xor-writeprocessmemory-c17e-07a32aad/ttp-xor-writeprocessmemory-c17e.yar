rule TTP_XOR_WriteProcessMemory_c17e {
  strings:
    $key_c17e = { 96 0c [2] a4 2e [2] a2 1b [2] 8c 1b [2] b3 07 }

  condition:
    any of them
}