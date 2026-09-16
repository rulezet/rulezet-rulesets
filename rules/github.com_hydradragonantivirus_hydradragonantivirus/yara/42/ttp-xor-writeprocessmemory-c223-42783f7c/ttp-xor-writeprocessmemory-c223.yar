rule TTP_XOR_WriteProcessMemory_c223 {
  strings:
    $key_c223 = { 95 51 [2] a7 73 [2] a1 46 [2] 8f 46 [2] b0 5a }

  condition:
    any of them
}