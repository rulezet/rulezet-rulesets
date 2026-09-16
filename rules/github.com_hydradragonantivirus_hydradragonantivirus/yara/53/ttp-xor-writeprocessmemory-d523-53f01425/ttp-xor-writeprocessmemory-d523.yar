rule TTP_XOR_WriteProcessMemory_d523 {
  strings:
    $key_d523 = { 82 51 [2] b0 73 [2] b6 46 [2] 98 46 [2] a7 5a }

  condition:
    any of them
}