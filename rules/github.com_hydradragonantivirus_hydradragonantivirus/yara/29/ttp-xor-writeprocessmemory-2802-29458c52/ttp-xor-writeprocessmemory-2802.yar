rule TTP_XOR_WriteProcessMemory_2802 {
  strings:
    $key_2802 = { 7f 70 [2] 4d 52 [2] 4b 67 [2] 65 67 [2] 5a 7b }

  condition:
    any of them
}