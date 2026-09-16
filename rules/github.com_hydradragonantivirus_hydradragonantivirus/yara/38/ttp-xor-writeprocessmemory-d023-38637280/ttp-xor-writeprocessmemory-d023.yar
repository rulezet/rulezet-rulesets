rule TTP_XOR_WriteProcessMemory_d023 {
  strings:
    $key_d023 = { 87 51 [2] b5 73 [2] b3 46 [2] 9d 46 [2] a2 5a }

  condition:
    any of them
}