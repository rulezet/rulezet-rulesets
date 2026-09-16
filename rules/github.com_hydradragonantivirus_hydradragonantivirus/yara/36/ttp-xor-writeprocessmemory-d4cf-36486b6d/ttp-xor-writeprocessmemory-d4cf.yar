rule TTP_XOR_WriteProcessMemory_d4cf {
  strings:
    $key_d4cf = { 83 bd [2] b1 9f [2] b7 aa [2] 99 aa [2] a6 b6 }

  condition:
    any of them
}