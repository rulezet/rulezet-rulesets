rule TTP_XOR_WriteProcessMemory_d223 {
  strings:
    $key_d223 = { 85 51 [2] b7 73 [2] b1 46 [2] 9f 46 [2] a0 5a }

  condition:
    any of them
}