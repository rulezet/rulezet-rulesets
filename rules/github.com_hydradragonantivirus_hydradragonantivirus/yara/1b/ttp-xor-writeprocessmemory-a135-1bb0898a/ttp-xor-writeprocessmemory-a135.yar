rule TTP_XOR_WriteProcessMemory_a135 {
  strings:
    $key_a135 = { f6 47 [2] c4 65 [2] c2 50 [2] ec 50 [2] d3 4c }

  condition:
    any of them
}