rule TTP_XOR_WriteProcessMemory_6423 {
  strings:
    $key_6423 = { 33 51 [2] 01 73 [2] 07 46 [2] 29 46 [2] 16 5a }

  condition:
    any of them
}