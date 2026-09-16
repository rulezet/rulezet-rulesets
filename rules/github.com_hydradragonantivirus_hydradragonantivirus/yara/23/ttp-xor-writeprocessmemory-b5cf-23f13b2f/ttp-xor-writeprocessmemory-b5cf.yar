rule TTP_XOR_WriteProcessMemory_b5cf {
  strings:
    $key_b5cf = { e2 bd [2] d0 9f [2] d6 aa [2] f8 aa [2] c7 b6 }

  condition:
    any of them
}