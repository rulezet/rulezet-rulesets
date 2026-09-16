rule TTP_XOR_WriteProcessMemory_fc01 {
  strings:
    $key_fc01 = { ab 73 [2] 99 51 [2] 9f 64 [2] b1 64 [2] 8e 78 }

  condition:
    any of them
}