rule TTP_XOR_WriteProcessMemory_e6d7 {
  strings:
    $key_e6d7 = { b1 a5 [2] 83 87 [2] 85 b2 [2] ab b2 [2] 94 ae }

  condition:
    any of them
}