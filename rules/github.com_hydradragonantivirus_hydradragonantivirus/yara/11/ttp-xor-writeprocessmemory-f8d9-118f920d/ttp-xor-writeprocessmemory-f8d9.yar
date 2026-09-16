rule TTP_XOR_WriteProcessMemory_f8d9 {
  strings:
    $key_f8d9 = { af ab [2] 9d 89 [2] 9b bc [2] b5 bc [2] 8a a0 }

  condition:
    any of them
}