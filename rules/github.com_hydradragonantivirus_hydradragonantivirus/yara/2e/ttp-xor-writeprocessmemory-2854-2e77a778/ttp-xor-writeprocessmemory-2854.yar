rule TTP_XOR_WriteProcessMemory_2854 {
  strings:
    $key_2854 = { 7f 26 [2] 4d 04 [2] 4b 31 [2] 65 31 [2] 5a 2d }

  condition:
    any of them
}