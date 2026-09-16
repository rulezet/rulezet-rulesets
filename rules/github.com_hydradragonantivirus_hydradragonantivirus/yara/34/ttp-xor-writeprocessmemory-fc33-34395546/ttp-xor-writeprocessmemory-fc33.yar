rule TTP_XOR_WriteProcessMemory_fc33 {
  strings:
    $key_fc33 = { ab 41 [2] 99 63 [2] 9f 56 [2] b1 56 [2] 8e 4a }

  condition:
    any of them
}