rule TTP_XOR_WriteProcessMemory_3e53 {
  strings:
    $key_3e53 = { 69 21 [2] 5b 03 [2] 5d 36 [2] 73 36 [2] 4c 2a }

  condition:
    any of them
}