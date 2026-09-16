rule TTP_XOR_WriteProcessMemory_a175 {
  strings:
    $key_a175 = { f6 07 [2] c4 25 [2] c2 10 [2] ec 10 [2] d3 0c }

  condition:
    any of them
}