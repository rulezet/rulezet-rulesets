rule TTP_XOR_WriteProcessMemory_b6dc {
  strings:
    $key_b6dc = { e1 ae [2] d3 8c [2] d5 b9 [2] fb b9 [2] c4 a5 }

  condition:
    any of them
}