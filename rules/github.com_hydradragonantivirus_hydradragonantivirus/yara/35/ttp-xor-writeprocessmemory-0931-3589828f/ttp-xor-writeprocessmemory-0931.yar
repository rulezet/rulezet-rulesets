rule TTP_XOR_WriteProcessMemory_0931 {
  strings:
    $key_0931 = { 5e 43 [2] 6c 61 [2] 6a 54 [2] 44 54 [2] 7b 48 }

  condition:
    any of them
}