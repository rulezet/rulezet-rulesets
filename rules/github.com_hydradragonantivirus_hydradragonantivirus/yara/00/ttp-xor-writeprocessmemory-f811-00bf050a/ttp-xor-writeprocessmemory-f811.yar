rule TTP_XOR_WriteProcessMemory_f811 {
  strings:
    $key_f811 = { af 63 [2] 9d 41 [2] 9b 74 [2] b5 74 [2] 8a 68 }

  condition:
    any of them
}