rule TTP_XOR_WriteProcessMemory_f8f7 {
  strings:
    $key_f8f7 = { af 85 [2] 9d a7 [2] 9b 92 [2] b5 92 [2] 8a 8e }

  condition:
    any of them
}