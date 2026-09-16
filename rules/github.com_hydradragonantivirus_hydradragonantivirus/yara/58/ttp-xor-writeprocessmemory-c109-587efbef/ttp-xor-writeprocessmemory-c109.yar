rule TTP_XOR_WriteProcessMemory_c109 {
  strings:
    $key_c109 = { 96 7b [2] a4 59 [2] a2 6c [2] 8c 6c [2] b3 70 }

  condition:
    any of them
}