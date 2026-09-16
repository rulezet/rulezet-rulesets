rule TTP_XOR_WriteProcessMemory_0710 {
  strings:
    $key_0710 = { 50 62 [2] 62 40 [2] 64 75 [2] 4a 75 [2] 75 69 }

  condition:
    any of them
}