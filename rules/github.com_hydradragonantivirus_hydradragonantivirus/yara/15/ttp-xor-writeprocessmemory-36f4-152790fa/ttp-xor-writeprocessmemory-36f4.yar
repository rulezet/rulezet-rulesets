rule TTP_XOR_WriteProcessMemory_36f4 {
  strings:
    $key_36f4 = { 61 86 [2] 53 a4 [2] 55 91 [2] 7b 91 [2] 44 8d }

  condition:
    any of them
}