rule TTP_XOR_WriteProcessMemory_b6cf {
  strings:
    $key_b6cf = { e1 bd [2] d3 9f [2] d5 aa [2] fb aa [2] c4 b6 }

  condition:
    any of them
}