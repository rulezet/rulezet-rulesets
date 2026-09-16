rule TTP_XOR_WriteProcessMemory_f3cf {
  strings:
    $key_f3cf = { a4 bd [2] 96 9f [2] 90 aa [2] be aa [2] 81 b6 }

  condition:
    any of them
}