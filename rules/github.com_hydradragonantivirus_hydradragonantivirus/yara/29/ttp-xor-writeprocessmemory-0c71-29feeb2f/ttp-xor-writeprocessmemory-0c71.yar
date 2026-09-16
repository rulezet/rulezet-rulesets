rule TTP_XOR_WriteProcessMemory_0c71 {
  strings:
    $key_0c71 = { 5b 03 [2] 69 21 [2] 6f 14 [2] 41 14 [2] 7e 08 }

  condition:
    any of them
}