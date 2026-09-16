rule TTP_XOR_WriteProcessMemory_2871 {
  strings:
    $key_2871 = { 7f 03 [2] 4d 21 [2] 4b 14 [2] 65 14 [2] 5a 08 }

  condition:
    any of them
}