rule TTP_XOR_WriteProcessMemory_1b01 {
  strings:
    $key_1b01 = { 4c 73 [2] 7e 51 [2] 78 64 [2] 56 64 [2] 69 78 }

  condition:
    any of them
}