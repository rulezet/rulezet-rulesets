rule TTP_XOR_WriteProcessMemory_3624 {
  strings:
    $key_3624 = { 61 56 [2] 53 74 [2] 55 41 [2] 7b 41 [2] 44 5d }

  condition:
    any of them
}