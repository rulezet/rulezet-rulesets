rule TTP_XOR_WriteProcessMemory_3c33 {
  strings:
    $key_3c33 = { 6b 41 [2] 59 63 [2] 5f 56 [2] 71 56 [2] 4e 4a }

  condition:
    any of them
}