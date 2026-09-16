rule TTP_XOR_WriteProcessMemory_0c61 {
  strings:
    $key_0c61 = { 5b 13 [2] 69 31 [2] 6f 04 [2] 41 04 [2] 7e 18 }

  condition:
    any of them
}