rule TTP_XOR_WriteProcessMemory_a116 {
  strings:
    $key_a116 = { f6 64 [2] c4 46 [2] c2 73 [2] ec 73 [2] d3 6f }

  condition:
    any of them
}