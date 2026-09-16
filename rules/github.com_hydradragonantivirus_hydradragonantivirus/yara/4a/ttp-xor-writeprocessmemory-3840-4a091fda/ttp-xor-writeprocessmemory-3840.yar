rule TTP_XOR_WriteProcessMemory_3840 {
  strings:
    $key_3840 = { 6f 32 [2] 5d 10 [2] 5b 25 [2] 75 25 [2] 4a 39 }

  condition:
    any of them
}