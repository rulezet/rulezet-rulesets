rule TTP_XOR_WriteProcessMemory_d659 {
  strings:
    $key_d659 = { 81 2b [2] b3 09 [2] b5 3c [2] 9b 3c [2] a4 20 }

  condition:
    any of them
}