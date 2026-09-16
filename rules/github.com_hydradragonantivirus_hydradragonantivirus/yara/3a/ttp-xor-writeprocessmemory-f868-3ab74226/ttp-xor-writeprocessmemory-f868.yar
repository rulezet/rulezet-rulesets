rule TTP_XOR_WriteProcessMemory_f868 {
  strings:
    $key_f868 = { af 1a [2] 9d 38 [2] 9b 0d [2] b5 0d [2] 8a 11 }

  condition:
    any of them
}