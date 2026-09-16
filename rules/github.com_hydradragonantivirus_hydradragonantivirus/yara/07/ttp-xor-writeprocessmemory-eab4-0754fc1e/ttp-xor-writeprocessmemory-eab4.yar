rule TTP_XOR_WriteProcessMemory_eab4 {
  strings:
    $key_eab4 = { bd c6 [2] 8f e4 [2] 89 d1 [2] a7 d1 [2] 98 cd }

  condition:
    any of them
}