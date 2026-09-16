rule TTP_XOR_WriteProcessMemory_0ad5 {
  strings:
    $key_0ad5 = { 5d a7 [2] 6f 85 [2] 69 b0 [2] 47 b0 [2] 78 ac }

  condition:
    any of them
}