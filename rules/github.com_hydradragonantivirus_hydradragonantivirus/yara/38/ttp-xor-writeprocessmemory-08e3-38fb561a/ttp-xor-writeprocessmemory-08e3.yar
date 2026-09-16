rule TTP_XOR_WriteProcessMemory_08e3 {
  strings:
    $key_08e3 = { 5f 91 [2] 6d b3 [2] 6b 86 [2] 45 86 [2] 7a 9a }

  condition:
    any of them
}