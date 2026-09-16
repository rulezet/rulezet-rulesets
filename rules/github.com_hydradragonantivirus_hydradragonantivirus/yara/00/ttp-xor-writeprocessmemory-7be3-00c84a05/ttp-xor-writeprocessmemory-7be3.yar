rule TTP_XOR_WriteProcessMemory_7be3 {
  strings:
    $key_7be3 = { 2c 91 [2] 1e b3 [2] 18 86 [2] 36 86 [2] 09 9a }

  condition:
    any of them
}