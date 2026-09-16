rule TTP_XOR_WriteProcessMemory_b2d8 {
  strings:
    $key_b2d8 = { e5 aa [2] d7 88 [2] d1 bd [2] ff bd [2] c0 a1 }

  condition:
    any of them
}