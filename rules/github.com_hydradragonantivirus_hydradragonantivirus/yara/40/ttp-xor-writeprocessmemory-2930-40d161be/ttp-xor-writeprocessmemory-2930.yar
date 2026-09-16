rule TTP_XOR_WriteProcessMemory_2930 {
  strings:
    $key_2930 = { 7e 42 [2] 4c 60 [2] 4a 55 [2] 64 55 [2] 5b 49 }

  condition:
    any of them
}