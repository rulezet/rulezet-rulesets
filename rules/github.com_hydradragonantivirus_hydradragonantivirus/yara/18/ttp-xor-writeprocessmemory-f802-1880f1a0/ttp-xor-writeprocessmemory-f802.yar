rule TTP_XOR_WriteProcessMemory_f802 {
  strings:
    $key_f802 = { af 70 [2] 9d 52 [2] 9b 67 [2] b5 67 [2] 8a 7b }

  condition:
    any of them
}