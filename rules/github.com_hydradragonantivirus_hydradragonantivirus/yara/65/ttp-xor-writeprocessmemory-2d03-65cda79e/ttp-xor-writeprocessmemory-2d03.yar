rule TTP_XOR_WriteProcessMemory_2d03 {
  strings:
    $key_2d03 = { 7a 71 [2] 48 53 [2] 4e 66 [2] 60 66 [2] 5f 7a }

  condition:
    any of them
}