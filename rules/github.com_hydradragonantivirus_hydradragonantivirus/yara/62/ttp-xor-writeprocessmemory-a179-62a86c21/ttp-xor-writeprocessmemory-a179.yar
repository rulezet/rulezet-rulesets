rule TTP_XOR_WriteProcessMemory_a179 {
  strings:
    $key_a179 = { f6 0b [2] c4 29 [2] c2 1c [2] ec 1c [2] d3 00 }

  condition:
    any of them
}