rule TTP_XOR_WriteProcessMemory_2955 {
  strings:
    $key_2955 = { 7e 27 [2] 4c 05 [2] 4a 30 [2] 64 30 [2] 5b 2c }

  condition:
    any of them
}