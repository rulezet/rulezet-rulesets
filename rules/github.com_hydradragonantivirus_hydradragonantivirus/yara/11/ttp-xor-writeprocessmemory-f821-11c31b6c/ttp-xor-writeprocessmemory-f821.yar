rule TTP_XOR_WriteProcessMemory_f821 {
  strings:
    $key_f821 = { af 53 [2] 9d 71 [2] 9b 44 [2] b5 44 [2] 8a 58 }

  condition:
    any of them
}