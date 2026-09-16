rule TTP_XOR_WriteProcessMemory_a121 {
  strings:
    $key_a121 = { f6 53 [2] c4 71 [2] c2 44 [2] ec 44 [2] d3 58 }

  condition:
    any of them
}