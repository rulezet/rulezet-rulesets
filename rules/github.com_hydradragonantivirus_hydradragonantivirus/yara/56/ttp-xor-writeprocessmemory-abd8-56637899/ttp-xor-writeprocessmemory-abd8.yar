rule TTP_XOR_WriteProcessMemory_abd8 {
  strings:
    $key_abd8 = { fc aa [2] ce 88 [2] c8 bd [2] e6 bd [2] d9 a1 }

  condition:
    any of them
}