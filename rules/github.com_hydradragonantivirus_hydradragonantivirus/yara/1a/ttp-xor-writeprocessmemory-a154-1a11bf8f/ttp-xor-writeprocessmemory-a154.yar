rule TTP_XOR_WriteProcessMemory_a154 {
  strings:
    $key_a154 = { f6 26 [2] c4 04 [2] c2 31 [2] ec 31 [2] d3 2d }

  condition:
    any of them
}