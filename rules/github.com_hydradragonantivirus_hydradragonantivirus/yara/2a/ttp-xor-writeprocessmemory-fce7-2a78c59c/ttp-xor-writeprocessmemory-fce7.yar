rule TTP_XOR_WriteProcessMemory_fce7 {
  strings:
    $key_fce7 = { ab 95 [2] 99 b7 [2] 9f 82 [2] b1 82 [2] 8e 9e }

  condition:
    any of them
}