rule TTP_XOR_WriteProcessMemory_a3cf {
  strings:
    $key_a3cf = { f4 bd [2] c6 9f [2] c0 aa [2] ee aa [2] d1 b6 }

  condition:
    any of them
}