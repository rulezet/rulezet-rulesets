rule TTP_XOR_WriteProcessMemory_0852 {
  strings:
    $key_0852 = { 5f 20 [2] 6d 02 [2] 6b 37 [2] 45 37 [2] 7a 2b }

  condition:
    any of them
}