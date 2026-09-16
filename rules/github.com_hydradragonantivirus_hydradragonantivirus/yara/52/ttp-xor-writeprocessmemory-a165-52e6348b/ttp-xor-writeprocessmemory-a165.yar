rule TTP_XOR_WriteProcessMemory_a165 {
  strings:
    $key_a165 = { f6 17 [2] c4 35 [2] c2 00 [2] ec 00 [2] d3 1c }

  condition:
    any of them
}