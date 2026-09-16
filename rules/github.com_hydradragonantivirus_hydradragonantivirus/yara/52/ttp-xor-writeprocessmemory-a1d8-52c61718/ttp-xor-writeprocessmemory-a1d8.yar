rule TTP_XOR_WriteProcessMemory_a1d8 {
  strings:
    $key_a1d8 = { f6 aa [2] c4 88 [2] c2 bd [2] ec bd [2] d3 a1 }

  condition:
    any of them
}