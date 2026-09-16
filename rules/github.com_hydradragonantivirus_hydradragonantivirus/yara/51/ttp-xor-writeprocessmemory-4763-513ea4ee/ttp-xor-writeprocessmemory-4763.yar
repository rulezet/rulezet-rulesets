rule TTP_XOR_WriteProcessMemory_4763 {
  strings:
    $key_4763 = { 10 11 [2] 22 33 [2] 24 06 [2] 0a 06 [2] 35 1a }

  condition:
    any of them
}