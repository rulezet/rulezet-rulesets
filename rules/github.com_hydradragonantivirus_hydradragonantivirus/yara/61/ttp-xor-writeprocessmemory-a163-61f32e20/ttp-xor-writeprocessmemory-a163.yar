rule TTP_XOR_WriteProcessMemory_a163 {
  strings:
    $key_a163 = { f6 11 [2] c4 33 [2] c2 06 [2] ec 06 [2] d3 1a }

  condition:
    any of them
}