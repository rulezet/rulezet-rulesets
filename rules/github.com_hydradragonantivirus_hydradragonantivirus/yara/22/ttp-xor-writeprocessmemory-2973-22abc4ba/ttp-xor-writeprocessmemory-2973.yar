rule TTP_XOR_WriteProcessMemory_2973 {
  strings:
    $key_2973 = { 7e 01 [2] 4c 23 [2] 4a 16 [2] 64 16 [2] 5b 0a }

  condition:
    any of them
}