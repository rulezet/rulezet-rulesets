rule TTP_XOR_WriteProcessMemory_d159 {
  strings:
    $key_d159 = { 86 2b [2] b4 09 [2] b2 3c [2] 9c 3c [2] a3 20 }

  condition:
    any of them
}