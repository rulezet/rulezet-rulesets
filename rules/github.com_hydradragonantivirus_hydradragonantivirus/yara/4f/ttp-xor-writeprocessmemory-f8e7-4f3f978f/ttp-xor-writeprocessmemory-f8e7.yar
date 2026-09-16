rule TTP_XOR_WriteProcessMemory_f8e7 {
  strings:
    $key_f8e7 = { af 95 [2] 9d b7 [2] 9b 82 [2] b5 82 [2] 8a 9e }

  condition:
    any of them
}