rule TTP_XOR_WriteProcessMemory_f806 {
  strings:
    $key_f806 = { af 74 [2] 9d 56 [2] 9b 63 [2] b5 63 [2] 8a 7f }

  condition:
    any of them
}