rule TTP_XOR_WriteProcessMemory_04d7 {
  strings:
    $key_04d7 = { 53 a5 [2] 61 87 [2] 67 b2 [2] 49 b2 [2] 76 ae }

  condition:
    any of them
}