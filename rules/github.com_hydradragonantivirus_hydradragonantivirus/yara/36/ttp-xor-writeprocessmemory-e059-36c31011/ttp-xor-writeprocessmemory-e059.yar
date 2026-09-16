rule TTP_XOR_WriteProcessMemory_e059 {
  strings:
    $key_e059 = { b7 2b [2] 85 09 [2] 83 3c [2] ad 3c [2] 92 20 }

  condition:
    any of them
}