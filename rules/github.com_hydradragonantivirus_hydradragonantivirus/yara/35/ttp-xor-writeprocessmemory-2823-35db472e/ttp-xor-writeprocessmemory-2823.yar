rule TTP_XOR_WriteProcessMemory_2823 {
  strings:
    $key_2823 = { 7f 51 [2] 4d 73 [2] 4b 46 [2] 65 46 [2] 5a 5a }

  condition:
    any of them
}