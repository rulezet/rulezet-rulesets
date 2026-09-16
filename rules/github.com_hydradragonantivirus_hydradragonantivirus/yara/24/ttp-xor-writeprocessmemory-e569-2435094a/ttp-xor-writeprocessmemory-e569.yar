rule TTP_XOR_WriteProcessMemory_e569 {
  strings:
    $key_e569 = { b2 1b [2] 80 39 [2] 86 0c [2] a8 0c [2] 97 10 }

  condition:
    any of them
}