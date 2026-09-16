rule TTP_XOR_WriteProcessMemory_7301 {
  strings:
    $key_7301 = { 24 73 [2] 16 51 [2] 10 64 [2] 3e 64 [2] 01 78 }

  condition:
    any of them
}