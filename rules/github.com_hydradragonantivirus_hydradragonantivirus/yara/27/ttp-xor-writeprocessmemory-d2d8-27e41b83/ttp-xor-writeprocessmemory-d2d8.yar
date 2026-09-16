rule TTP_XOR_WriteProcessMemory_d2d8 {
  strings:
    $key_d2d8 = { 85 aa [2] b7 88 [2] b1 bd [2] 9f bd [2] a0 a1 }

  condition:
    any of them
}