rule TTP_XOR_WriteProcessMemory_5b01 {
  strings:
    $key_5b01 = { 0c 73 [2] 3e 51 [2] 38 64 [2] 16 64 [2] 29 78 }

  condition:
    any of them
}