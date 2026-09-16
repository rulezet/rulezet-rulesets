rule TTP_XOR_WriteProcessMemory_11d7 {
  strings:
    $key_11d7 = { 46 a5 [2] 74 87 [2] 72 b2 [2] 5c b2 [2] 63 ae }

  condition:
    any of them
}