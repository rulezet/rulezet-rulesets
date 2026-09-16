rule TTP_XOR_WriteProcessMemory_e559 {
  strings:
    $key_e559 = { b2 2b [2] 80 09 [2] 86 3c [2] a8 3c [2] 97 20 }

  condition:
    any of them
}