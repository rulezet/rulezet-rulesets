rule TTP_XOR_WriteProcessMemory_c12b {
  strings:
    $key_c12b = { 96 59 [2] a4 7b [2] a2 4e [2] 8c 4e [2] b3 52 }

  condition:
    any of them
}