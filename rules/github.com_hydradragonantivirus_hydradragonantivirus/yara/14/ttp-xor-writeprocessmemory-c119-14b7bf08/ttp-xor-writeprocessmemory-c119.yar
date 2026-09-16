rule TTP_XOR_WriteProcessMemory_c119 {
  strings:
    $key_c119 = { 96 6b [2] a4 49 [2] a2 7c [2] 8c 7c [2] b3 60 }

  condition:
    any of them
}