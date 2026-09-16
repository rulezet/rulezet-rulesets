rule TTP_XOR_WriteProcessMemory_3654 {
  strings:
    $key_3654 = { 61 26 [2] 53 04 [2] 55 31 [2] 7b 31 [2] 44 2d }

  condition:
    any of them
}