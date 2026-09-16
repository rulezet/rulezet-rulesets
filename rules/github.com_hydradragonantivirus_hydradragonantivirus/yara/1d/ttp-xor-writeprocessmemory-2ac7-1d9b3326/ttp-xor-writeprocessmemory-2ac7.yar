rule TTP_XOR_WriteProcessMemory_2ac7 {
  strings:
    $key_2ac7 = { 7d b5 [2] 4f 97 [2] 49 a2 [2] 67 a2 [2] 58 be }

  condition:
    any of them
}