rule TTP_XOR_WriteProcessMemory_3b01 {
  strings:
    $key_3b01 = { 6c 73 [2] 5e 51 [2] 58 64 [2] 76 64 [2] 49 78 }

  condition:
    any of them
}