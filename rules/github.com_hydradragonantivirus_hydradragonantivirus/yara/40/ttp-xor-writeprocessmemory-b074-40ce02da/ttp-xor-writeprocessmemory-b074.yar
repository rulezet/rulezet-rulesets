rule TTP_XOR_WriteProcessMemory_b074 {
  strings:
    $key_b074 = { e7 06 [2] d5 24 [2] d3 11 [2] fd 11 [2] c2 0d }

  condition:
    any of them
}