rule TTP_XOR_WriteProcessMemory_f8e2 {
  strings:
    $key_f8e2 = { af 90 [2] 9d b2 [2] 9b 87 [2] b5 87 [2] 8a 9b }

  condition:
    any of them
}