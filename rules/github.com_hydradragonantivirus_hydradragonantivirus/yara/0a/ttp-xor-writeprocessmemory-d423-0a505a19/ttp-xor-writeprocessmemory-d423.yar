rule TTP_XOR_WriteProcessMemory_d423 {
  strings:
    $key_d423 = { 83 51 [2] b1 73 [2] b7 46 [2] 99 46 [2] a6 5a }

  condition:
    any of them
}