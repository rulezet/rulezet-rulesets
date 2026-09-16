rule TTP_XOR_WriteProcessMemory_a120 {
  strings:
    $key_a120 = { f6 52 [2] c4 70 [2] c2 45 [2] ec 45 [2] d3 59 }

  condition:
    any of them
}