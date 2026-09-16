rule TTP_XOR_WriteProcessMemory_a2d8 {
  strings:
    $key_a2d8 = { f5 aa [2] c7 88 [2] c1 bd [2] ef bd [2] d0 a1 }

  condition:
    any of them
}