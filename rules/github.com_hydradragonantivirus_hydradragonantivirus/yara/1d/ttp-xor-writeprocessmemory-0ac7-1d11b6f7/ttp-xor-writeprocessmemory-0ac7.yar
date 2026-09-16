rule TTP_XOR_WriteProcessMemory_0ac7 {
  strings:
    $key_0ac7 = { 5d b5 [2] 6f 97 [2] 69 a2 [2] 47 a2 [2] 78 be }

  condition:
    any of them
}