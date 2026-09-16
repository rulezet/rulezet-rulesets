rule TTP_XOR_WriteProcessMemory_0cf3 {
  strings:
    $key_0cf3 = { 5b 81 [2] 69 a3 [2] 6f 96 [2] 41 96 [2] 7e 8a }

  condition:
    any of them
}