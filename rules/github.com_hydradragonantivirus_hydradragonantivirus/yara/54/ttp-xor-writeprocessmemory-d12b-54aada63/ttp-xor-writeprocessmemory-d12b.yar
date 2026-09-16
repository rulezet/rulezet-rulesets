rule TTP_XOR_WriteProcessMemory_d12b {
  strings:
    $key_d12b = { 86 59 [2] b4 7b [2] b2 4e [2] 9c 4e [2] a3 52 }

  condition:
    any of them
}