rule TTP_XOR_WriteProcessMemory_d7cf {
  strings:
    $key_d7cf = { 80 bd [2] b2 9f [2] b4 aa [2] 9a aa [2] a5 b6 }

  condition:
    any of them
}