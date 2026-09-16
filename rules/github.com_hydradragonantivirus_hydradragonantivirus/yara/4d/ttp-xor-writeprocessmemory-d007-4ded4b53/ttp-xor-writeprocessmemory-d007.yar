rule TTP_XOR_WriteProcessMemory_d007 {
  strings:
    $key_d007 = { 87 75 [2] b5 57 [2] b3 62 [2] 9d 62 [2] a2 7e }

  condition:
    any of them
}