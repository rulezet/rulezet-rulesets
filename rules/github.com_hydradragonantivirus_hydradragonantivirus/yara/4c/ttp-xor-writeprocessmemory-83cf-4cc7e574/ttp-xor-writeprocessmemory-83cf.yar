rule TTP_XOR_WriteProcessMemory_83cf {
  strings:
    $key_83cf = { d4 bd [2] e6 9f [2] e0 aa [2] ce aa [2] f1 b6 }

  condition:
    any of them
}