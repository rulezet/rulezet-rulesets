rule TTP_XOR_WriteProcessMemory_3813 {
  strings:
    $key_3813 = { 6f 61 [2] 5d 43 [2] 5b 76 [2] 75 76 [2] 4a 6a }

  condition:
    any of them
}