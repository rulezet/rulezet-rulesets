rule TTP_XOR_WriteProcessMemory_7852 {
  strings:
    $key_7852 = { 2f 20 [2] 1d 02 [2] 1b 37 [2] 35 37 [2] 0a 2b }

  condition:
    any of them
}