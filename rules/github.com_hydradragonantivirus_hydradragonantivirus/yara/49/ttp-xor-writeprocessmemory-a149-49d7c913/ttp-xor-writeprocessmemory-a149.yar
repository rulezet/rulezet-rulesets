rule TTP_XOR_WriteProcessMemory_a149 {
  strings:
    $key_a149 = { f6 3b [2] c4 19 [2] c2 2c [2] ec 2c [2] d3 30 }

  condition:
    any of them
}