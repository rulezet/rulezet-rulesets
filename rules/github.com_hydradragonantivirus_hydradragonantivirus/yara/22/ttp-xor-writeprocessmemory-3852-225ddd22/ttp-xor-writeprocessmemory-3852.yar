rule TTP_XOR_WriteProcessMemory_3852 {
  strings:
    $key_3852 = { 6f 20 [2] 5d 02 [2] 5b 37 [2] 75 37 [2] 4a 2b }

  condition:
    any of them
}