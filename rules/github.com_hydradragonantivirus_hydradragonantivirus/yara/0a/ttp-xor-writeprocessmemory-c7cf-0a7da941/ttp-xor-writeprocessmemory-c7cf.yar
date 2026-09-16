rule TTP_XOR_WriteProcessMemory_c7cf {
  strings:
    $key_c7cf = { 90 bd [2] a2 9f [2] a4 aa [2] 8a aa [2] b5 b6 }

  condition:
    any of them
}