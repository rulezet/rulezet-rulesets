rule TTP_XOR_WriteProcessMemory_a0d8 {
  strings:
    $key_a0d8 = { f7 aa [2] c5 88 [2] c3 bd [2] ed bd [2] d2 a1 }

  condition:
    any of them
}