rule TTP_XOR_WriteProcessMemory_b059 {
  strings:
    $key_b059 = { e7 2b [2] d5 09 [2] d3 3c [2] fd 3c [2] c2 20 }

  condition:
    any of them
}