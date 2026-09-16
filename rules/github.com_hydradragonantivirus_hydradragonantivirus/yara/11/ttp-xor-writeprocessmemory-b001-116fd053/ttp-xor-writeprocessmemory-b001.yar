rule TTP_XOR_WriteProcessMemory_b001 {
  strings:
    $key_b001 = { e7 73 [2] d5 51 [2] d3 64 [2] fd 64 [2] c2 78 }

  condition:
    any of them
}