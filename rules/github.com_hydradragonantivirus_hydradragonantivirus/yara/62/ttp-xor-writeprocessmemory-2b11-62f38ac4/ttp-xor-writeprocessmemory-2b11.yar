rule TTP_XOR_WriteProcessMemory_2b11 {
  strings:
    $key_2b11 = { 7c 63 [2] 4e 41 [2] 48 74 [2] 66 74 [2] 59 68 }

  condition:
    any of them
}