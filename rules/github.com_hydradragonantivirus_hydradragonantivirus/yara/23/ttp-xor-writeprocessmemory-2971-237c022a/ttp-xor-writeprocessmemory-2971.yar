rule TTP_XOR_WriteProcessMemory_2971 {
  strings:
    $key_2971 = { 7e 03 [2] 4c 21 [2] 4a 14 [2] 64 14 [2] 5b 08 }

  condition:
    any of them
}