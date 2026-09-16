rule TTP_XOR_WriteProcessMemory_b601 {
  strings:
    $key_b601 = { e1 73 [2] d3 51 [2] d5 64 [2] fb 64 [2] c4 78 }

  condition:
    any of them
}