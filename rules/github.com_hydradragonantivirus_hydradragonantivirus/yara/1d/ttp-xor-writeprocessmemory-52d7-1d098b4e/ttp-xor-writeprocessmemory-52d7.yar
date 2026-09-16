rule TTP_XOR_WriteProcessMemory_52d7 {
  strings:
    $key_52d7 = { 05 a5 [2] 37 87 [2] 31 b2 [2] 1f b2 [2] 20 ae }

  condition:
    any of them
}