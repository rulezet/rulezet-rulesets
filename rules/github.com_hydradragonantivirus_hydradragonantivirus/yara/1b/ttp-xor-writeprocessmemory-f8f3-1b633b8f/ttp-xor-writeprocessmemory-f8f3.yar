rule TTP_XOR_WriteProcessMemory_f8f3 {
  strings:
    $key_f8f3 = { af 81 [2] 9d a3 [2] 9b 96 [2] b5 96 [2] 8a 8a }

  condition:
    any of them
}