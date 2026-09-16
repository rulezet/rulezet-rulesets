rule TTP_XOR_WriteProcessMemory_d2cf {
  strings:
    $key_d2cf = { 85 bd [2] b7 9f [2] b1 aa [2] 9f aa [2] a0 b6 }

  condition:
    any of them
}