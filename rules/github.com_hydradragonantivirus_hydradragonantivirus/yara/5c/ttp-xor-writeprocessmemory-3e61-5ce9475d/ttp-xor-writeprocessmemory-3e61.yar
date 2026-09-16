rule TTP_XOR_WriteProcessMemory_3e61 {
  strings:
    $key_3e61 = { 69 13 [2] 5b 31 [2] 5d 04 [2] 73 04 [2] 4c 18 }

  condition:
    any of them
}