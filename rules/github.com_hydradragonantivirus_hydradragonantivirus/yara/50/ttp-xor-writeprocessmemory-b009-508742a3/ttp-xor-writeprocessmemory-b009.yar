rule TTP_XOR_WriteProcessMemory_b009 {
  strings:
    $key_b009 = { e7 7b [2] d5 59 [2] d3 6c [2] fd 6c [2] c2 70 }

  condition:
    any of them
}