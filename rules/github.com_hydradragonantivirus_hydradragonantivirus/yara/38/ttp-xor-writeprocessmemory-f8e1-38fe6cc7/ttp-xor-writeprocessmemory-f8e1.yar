rule TTP_XOR_WriteProcessMemory_f8e1 {
  strings:
    $key_f8e1 = { af 93 [2] 9d b1 [2] 9b 84 [2] b5 84 [2] 8a 98 }

  condition:
    any of them
}