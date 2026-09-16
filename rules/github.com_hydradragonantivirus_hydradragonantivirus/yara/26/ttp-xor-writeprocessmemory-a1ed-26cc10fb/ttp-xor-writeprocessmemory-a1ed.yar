rule TTP_XOR_WriteProcessMemory_a1ed {
  strings:
    $key_a1ed = { f6 9f [2] c4 bd [2] c2 88 [2] ec 88 [2] d3 94 }

  condition:
    any of them
}