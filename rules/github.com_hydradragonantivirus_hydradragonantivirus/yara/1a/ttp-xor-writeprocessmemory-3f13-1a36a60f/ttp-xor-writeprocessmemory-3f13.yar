rule TTP_XOR_WriteProcessMemory_3f13 {
  strings:
    $key_3f13 = { 68 61 [2] 5a 43 [2] 5c 76 [2] 72 76 [2] 4d 6a }

  condition:
    any of them
}