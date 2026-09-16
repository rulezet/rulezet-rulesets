rule TTP_XOR_WriteProcessMemory_d3d8 {
  strings:
    $key_d3d8 = { 84 aa [2] b6 88 [2] b0 bd [2] 9e bd [2] a1 a1 }

  condition:
    any of them
}