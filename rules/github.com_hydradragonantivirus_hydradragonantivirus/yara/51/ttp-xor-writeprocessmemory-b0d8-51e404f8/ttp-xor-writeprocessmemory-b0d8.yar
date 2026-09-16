rule TTP_XOR_WriteProcessMemory_b0d8 {
  strings:
    $key_b0d8 = { e7 aa [2] d5 88 [2] d3 bd [2] fd bd [2] c2 a1 }

  condition:
    any of them
}