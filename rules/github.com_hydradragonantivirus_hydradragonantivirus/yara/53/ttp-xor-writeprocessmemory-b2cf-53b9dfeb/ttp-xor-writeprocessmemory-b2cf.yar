rule TTP_XOR_WriteProcessMemory_b2cf {
  strings:
    $key_b2cf = { e5 bd [2] d7 9f [2] d1 aa [2] ff aa [2] c0 b6 }

  condition:
    any of them
}