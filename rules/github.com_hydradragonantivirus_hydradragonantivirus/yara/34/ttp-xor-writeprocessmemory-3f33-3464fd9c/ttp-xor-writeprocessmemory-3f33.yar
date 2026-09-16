rule TTP_XOR_WriteProcessMemory_3f33 {
  strings:
    $key_3f33 = { 68 41 [2] 5a 63 [2] 5c 56 [2] 72 56 [2] 4d 4a }

  condition:
    any of them
}