rule TTP_XOR_WriteProcessMemory_c659 {
  strings:
    $key_c659 = { 91 2b [2] a3 09 [2] a5 3c [2] 8b 3c [2] b4 20 }

  condition:
    any of them
}