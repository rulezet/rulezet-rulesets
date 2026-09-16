rule TTP_XOR_WriteProcessMemory_fcd5 {
  strings:
    $key_fcd5 = { ab a7 [2] 99 85 [2] 9f b0 [2] b1 b0 [2] 8e ac }

  condition:
    any of them
}