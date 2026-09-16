rule TTP_XOR_WriteProcessMemory_2d74 {
  strings:
    $key_2d74 = { 7a 06 [2] 48 24 [2] 4e 11 [2] 60 11 [2] 5f 0d }

  condition:
    any of them
}