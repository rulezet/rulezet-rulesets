rule TTP_XOR_WriteProcessMemory_a111 {
  strings:
    $key_a111 = { f6 63 [2] c4 41 [2] c2 74 [2] ec 74 [2] d3 68 }

  condition:
    any of them
}