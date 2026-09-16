rule TTP_XOR_WriteProcessMemory_fbd7 {
  strings:
    $key_fbd7 = { ac a5 [2] 9e 87 [2] 98 b2 [2] b6 b2 [2] 89 ae }

  condition:
    any of them
}