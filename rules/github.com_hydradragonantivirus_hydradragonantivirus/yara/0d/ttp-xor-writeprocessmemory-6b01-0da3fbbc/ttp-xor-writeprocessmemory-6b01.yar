rule TTP_XOR_WriteProcessMemory_6b01 {
  strings:
    $key_6b01 = { 3c 73 [2] 0e 51 [2] 08 64 [2] 26 64 [2] 19 78 }

  condition:
    any of them
}