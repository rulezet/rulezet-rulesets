rule TTP_XOR_WriteProcessMemory_38f4 {
  strings:
    $key_38f4 = { 6f 86 [2] 5d a4 [2] 5b 91 [2] 75 91 [2] 4a 8d }

  condition:
    any of them
}