rule TTP_XOR_WriteProcessMemory_d891 {
  strings:
    $key_d891 = { 8f e3 [2] bd c1 [2] bb f4 [2] 95 f4 [2] aa e8 }

  condition:
    any of them
}