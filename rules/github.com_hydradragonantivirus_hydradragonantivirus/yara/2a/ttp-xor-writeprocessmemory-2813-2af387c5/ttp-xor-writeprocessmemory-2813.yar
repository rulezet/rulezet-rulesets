rule TTP_XOR_WriteProcessMemory_2813 {
  strings:
    $key_2813 = { 7f 61 [2] 4d 43 [2] 4b 76 [2] 65 76 [2] 5a 6a }

  condition:
    any of them
}