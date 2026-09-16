rule TTP_XOR_WriteProcessMemory_5d23 {
  strings:
    $key_5d23 = { 0a 51 [2] 38 73 [2] 3e 46 [2] 10 46 [2] 2f 5a }

  condition:
    any of them
}