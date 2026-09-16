rule TTP_XOR_WriteProcessMemory_f879 {
  strings:
    $key_f879 = { af 0b [2] 9d 29 [2] 9b 1c [2] b5 1c [2] 8a 00 }

  condition:
    any of them
}