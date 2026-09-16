rule TTP_XOR_WriteProcessMemory_1031 {
  strings:
    $key_1031 = { 47 43 [2] 75 61 [2] 73 54 [2] 5d 54 [2] 62 48 }

  condition:
    any of them
}