rule TTP_XOR_WriteProcessMemory_a1e5 {
  strings:
    $key_a1e5 = { f6 97 [2] c4 b5 [2] c2 80 [2] ec 80 [2] d3 9c }

  condition:
    any of them
}