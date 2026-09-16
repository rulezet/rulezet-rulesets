rule TTP_XOR_WriteProcessMemory_d759 {
  strings:
    $key_d759 = { 80 2b [2] b2 09 [2] b4 3c [2] 9a 3c [2] a5 20 }

  condition:
    any of them
}