rule TTP_XOR_WriteProcessMemory_f8f1 {
  strings:
    $key_f8f1 = { af 83 [2] 9d a1 [2] 9b 94 [2] b5 94 [2] 8a 88 }

  condition:
    any of them
}