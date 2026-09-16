rule TTP_XOR_WriteProcessMemory_34d7 {
  strings:
    $key_34d7 = { 63 a5 [2] 51 87 [2] 57 b2 [2] 79 b2 [2] 46 ae }

  condition:
    any of them
}