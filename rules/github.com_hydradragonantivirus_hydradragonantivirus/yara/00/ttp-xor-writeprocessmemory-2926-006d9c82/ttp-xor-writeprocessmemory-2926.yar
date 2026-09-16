rule TTP_XOR_WriteProcessMemory_2926 {
  strings:
    $key_2926 = { 7e 54 [2] 4c 76 [2] 4a 43 [2] 64 43 [2] 5b 5f }

  condition:
    any of them
}