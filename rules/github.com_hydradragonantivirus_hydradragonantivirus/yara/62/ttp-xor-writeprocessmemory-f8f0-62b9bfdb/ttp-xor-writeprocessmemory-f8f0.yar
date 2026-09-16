rule TTP_XOR_WriteProcessMemory_f8f0 {
  strings:
    $key_f8f0 = { af 82 [2] 9d a0 [2] 9b 95 [2] b5 95 [2] 8a 89 }

  condition:
    any of them
}