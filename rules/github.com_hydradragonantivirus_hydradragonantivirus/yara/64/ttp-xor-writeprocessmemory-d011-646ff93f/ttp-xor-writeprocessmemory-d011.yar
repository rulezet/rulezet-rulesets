rule TTP_XOR_WriteProcessMemory_d011 {
  strings:
    $key_d011 = { 87 63 [2] b5 41 [2] b3 74 [2] 9d 74 [2] a2 68 }

  condition:
    any of them
}