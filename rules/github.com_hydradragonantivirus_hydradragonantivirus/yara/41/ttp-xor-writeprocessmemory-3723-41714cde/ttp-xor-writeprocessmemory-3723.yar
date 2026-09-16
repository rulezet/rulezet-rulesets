rule TTP_XOR_WriteProcessMemory_3723 {
  strings:
    $key_3723 = { 60 51 [2] 52 73 [2] 54 46 [2] 7a 46 [2] 45 5a }

  condition:
    any of them
}