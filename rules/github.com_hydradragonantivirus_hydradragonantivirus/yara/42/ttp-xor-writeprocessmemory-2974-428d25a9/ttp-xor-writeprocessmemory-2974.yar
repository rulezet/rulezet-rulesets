rule TTP_XOR_WriteProcessMemory_2974 {
  strings:
    $key_2974 = { 7e 06 [2] 4c 24 [2] 4a 11 [2] 64 11 [2] 5b 0d }

  condition:
    any of them
}