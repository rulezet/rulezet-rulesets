rule TTP_XOR_WriteProcessMemory_b039 {
  strings:
    $key_b039 = { e7 4b [2] d5 69 [2] d3 5c [2] fd 5c [2] c2 40 }

  condition:
    any of them
}