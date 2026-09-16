rule TTP_XOR_WriteProcessMemory_08f4 {
  strings:
    $key_08f4 = { 5f 86 [2] 6d a4 [2] 6b 91 [2] 45 91 [2] 7a 8d }

  condition:
    any of them
}