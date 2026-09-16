rule TTP_XOR_WriteProcessMemory_a150 {
  strings:
    $key_a150 = { f6 22 [2] c4 00 [2] c2 35 [2] ec 35 [2] d3 29 }

  condition:
    any of them
}