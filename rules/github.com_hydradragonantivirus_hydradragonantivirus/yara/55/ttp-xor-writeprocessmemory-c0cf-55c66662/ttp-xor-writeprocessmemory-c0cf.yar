rule TTP_XOR_WriteProcessMemory_c0cf {
  strings:
    $key_c0cf = { 97 bd [2] a5 9f [2] a3 aa [2] 8d aa [2] b2 b6 }

  condition:
    any of them
}