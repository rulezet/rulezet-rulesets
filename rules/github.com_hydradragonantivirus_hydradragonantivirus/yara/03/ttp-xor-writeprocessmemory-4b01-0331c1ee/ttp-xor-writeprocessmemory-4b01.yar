rule TTP_XOR_WriteProcessMemory_4b01 {
  strings:
    $key_4b01 = { 1c 73 [2] 2e 51 [2] 28 64 [2] 06 64 [2] 39 78 }

  condition:
    any of them
}