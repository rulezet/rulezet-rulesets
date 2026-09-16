rule TTP_XOR_WriteProcessMemory_b0dc {
  strings:
    $key_b0dc = { e7 ae [2] d5 8c [2] d3 b9 [2] fd b9 [2] c2 a5 }

  condition:
    any of them
}