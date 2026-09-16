rule TTP_XOR_WriteProcessMemory_38e3 {
  strings:
    $key_38e3 = { 6f 91 [2] 5d b3 [2] 5b 86 [2] 75 86 [2] 4a 9a }

  condition:
    any of them
}