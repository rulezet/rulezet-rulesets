rule TTP_XOR_WriteProcessMemory_39f4 {
  strings:
    $key_39f4 = { 6e 86 [2] 5c a4 [2] 5a 91 [2] 74 91 [2] 4b 8d }

  condition:
    any of them
}