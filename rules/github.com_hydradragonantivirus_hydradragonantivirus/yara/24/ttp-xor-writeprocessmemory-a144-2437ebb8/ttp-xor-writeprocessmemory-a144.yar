rule TTP_XOR_WriteProcessMemory_a144 {
  strings:
    $key_a144 = { f6 36 [2] c4 14 [2] c2 21 [2] ec 21 [2] d3 3d }

  condition:
    any of them
}