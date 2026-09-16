rule TTP_XOR_WriteProcessMemory_d3ee {
  strings:
    $key_d3ee = { 84 9c [2] b6 be [2] b0 8b [2] 9e 8b [2] a1 97 }

  condition:
    any of them
}