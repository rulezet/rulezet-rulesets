rule TTP_XOR_WriteProcessMemory_fc37 {
  strings:
    $key_fc37 = { ab 45 [2] 99 67 [2] 9f 52 [2] b1 52 [2] 8e 4e }

  condition:
    any of them
}