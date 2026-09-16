rule TTP_XOR_WriteProcessMemory_2171 {
  strings:
    $key_2171 = { 76 03 [2] 44 21 [2] 42 14 [2] 6c 14 [2] 53 08 }

  condition:
    any of them
}