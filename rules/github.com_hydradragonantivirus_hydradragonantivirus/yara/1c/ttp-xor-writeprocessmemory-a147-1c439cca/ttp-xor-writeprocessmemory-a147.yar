rule TTP_XOR_WriteProcessMemory_a147 {
  strings:
    $key_a147 = { f6 35 [2] c4 17 [2] c2 22 [2] ec 22 [2] d3 3e }

  condition:
    any of them
}