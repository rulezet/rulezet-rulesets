rule TTP_XOR_WriteProcessMemory_a171 {
  strings:
    $key_a171 = { f6 03 [2] c4 21 [2] c2 14 [2] ec 14 [2] d3 08 }

  condition:
    any of them
}