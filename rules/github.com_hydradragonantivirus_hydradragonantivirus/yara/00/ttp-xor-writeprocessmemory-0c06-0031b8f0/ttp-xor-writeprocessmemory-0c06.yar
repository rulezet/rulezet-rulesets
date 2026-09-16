rule TTP_XOR_WriteProcessMemory_0c06 {
  strings:
    $key_0c06 = { 5b 74 [2] 69 56 [2] 6f 63 [2] 41 63 [2] 7e 7f }

  condition:
    any of them
}