rule TTP_XOR_WriteProcessMemory_a128 {
  strings:
    $key_a128 = { f6 5a [2] c4 78 [2] c2 4d [2] ec 4d [2] d3 51 }

  condition:
    any of them
}