rule TTP_XOR_WriteProcessMemory_2ef4 {
  strings:
    $key_2ef4 = { 79 86 [2] 4b a4 [2] 4d 91 [2] 63 91 [2] 5c 8d }

  condition:
    any of them
}