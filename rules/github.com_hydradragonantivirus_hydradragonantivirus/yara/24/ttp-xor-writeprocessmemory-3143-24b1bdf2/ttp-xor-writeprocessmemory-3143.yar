rule TTP_XOR_WriteProcessMemory_3143 {
  strings:
    $key_3143 = { 66 31 [2] 54 13 [2] 52 26 [2] 7c 26 [2] 43 3a }

  condition:
    any of them
}