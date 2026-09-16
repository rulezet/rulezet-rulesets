rule TTP_XOR_WriteProcessMemory_2803 {
  strings:
    $key_2803 = { 7f 71 [2] 4d 53 [2] 4b 66 [2] 65 66 [2] 5a 7a }

  condition:
    any of them
}