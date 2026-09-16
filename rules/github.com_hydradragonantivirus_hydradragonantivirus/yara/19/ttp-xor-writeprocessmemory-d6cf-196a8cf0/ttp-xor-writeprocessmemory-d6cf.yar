rule TTP_XOR_WriteProcessMemory_d6cf {
  strings:
    $key_d6cf = { 81 bd [2] b3 9f [2] b5 aa [2] 9b aa [2] a4 b6 }

  condition:
    any of them
}