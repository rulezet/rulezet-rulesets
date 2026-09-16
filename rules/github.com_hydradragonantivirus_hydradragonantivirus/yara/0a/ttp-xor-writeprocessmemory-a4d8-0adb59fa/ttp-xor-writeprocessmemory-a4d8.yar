rule TTP_XOR_WriteProcessMemory_a4d8 {
  strings:
    $key_a4d8 = { f3 aa [2] c1 88 [2] c7 bd [2] e9 bd [2] d6 a1 }

  condition:
    any of them
}