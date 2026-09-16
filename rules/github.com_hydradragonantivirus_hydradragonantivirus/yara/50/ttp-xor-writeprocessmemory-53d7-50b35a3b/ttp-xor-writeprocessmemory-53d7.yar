rule TTP_XOR_WriteProcessMemory_53d7 {
  strings:
    $key_53d7 = { 04 a5 [2] 36 87 [2] 30 b2 [2] 1e b2 [2] 21 ae }

  condition:
    any of them
}