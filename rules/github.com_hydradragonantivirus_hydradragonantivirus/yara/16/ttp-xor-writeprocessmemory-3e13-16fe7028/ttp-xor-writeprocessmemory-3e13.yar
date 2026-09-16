rule TTP_XOR_WriteProcessMemory_3e13 {
  strings:
    $key_3e13 = { 69 61 [2] 5b 43 [2] 5d 76 [2] 73 76 [2] 4c 6a }

  condition:
    any of them
}