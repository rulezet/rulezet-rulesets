rule TTP_XOR_WriteProcessMemory_0b01 {
  strings:
    $key_0b01 = { 5c 73 [2] 6e 51 [2] 68 64 [2] 46 64 [2] 79 78 }

  condition:
    any of them
}