rule TTP_XOR_WriteProcessMemory_fc04 {
  strings:
    $key_fc04 = { ab 76 [2] 99 54 [2] 9f 61 [2] b1 61 [2] 8e 7d }

  condition:
    any of them
}