rule TTP_XOR_WriteProcessMemory_2804 {
  strings:
    $key_2804 = { 7f 76 [2] 4d 54 [2] 4b 61 [2] 65 61 [2] 5a 7d }

  condition:
    any of them
}