rule TTP_XOR_WriteProcessMemory_a6cf {
  strings:
    $key_a6cf = { f1 bd [2] c3 9f [2] c5 aa [2] eb aa [2] d4 b6 }

  condition:
    any of them
}