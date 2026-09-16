rule TTP_XOR_WriteProcessMemory_d061 {
  strings:
    $key_d061 = { 87 13 [2] b5 31 [2] b3 04 [2] 9d 04 [2] a2 18 }

  condition:
    any of them
}