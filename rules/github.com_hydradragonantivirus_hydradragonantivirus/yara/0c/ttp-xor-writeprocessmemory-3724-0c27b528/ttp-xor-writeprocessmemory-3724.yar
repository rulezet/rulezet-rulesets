rule TTP_XOR_WriteProcessMemory_3724 {
  strings:
    $key_3724 = { 60 56 [2] 52 74 [2] 54 41 [2] 7a 41 [2] 45 5d }

  condition:
    any of them
}