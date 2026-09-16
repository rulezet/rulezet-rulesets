rule TTP_XOR_WriteProcessMemory_3cf3 {
  strings:
    $key_3cf3 = { 6b 81 [2] 59 a3 [2] 5f 96 [2] 71 96 [2] 4e 8a }

  condition:
    any of them
}