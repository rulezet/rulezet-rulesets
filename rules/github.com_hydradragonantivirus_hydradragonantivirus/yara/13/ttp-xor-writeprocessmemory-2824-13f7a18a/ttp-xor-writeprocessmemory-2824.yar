rule TTP_XOR_WriteProcessMemory_2824 {
  strings:
    $key_2824 = { 7f 56 [2] 4d 74 [2] 4b 41 [2] 65 41 [2] 5a 5d }

  condition:
    any of them
}