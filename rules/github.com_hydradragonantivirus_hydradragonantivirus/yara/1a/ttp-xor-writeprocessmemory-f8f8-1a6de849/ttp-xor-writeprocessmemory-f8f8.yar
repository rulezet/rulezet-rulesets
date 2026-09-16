rule TTP_XOR_WriteProcessMemory_f8f8 {
  strings:
    $key_f8f8 = { af 8a [2] 9d a8 [2] 9b 9d [2] b5 9d [2] 8a 81 }

  condition:
    any of them
}