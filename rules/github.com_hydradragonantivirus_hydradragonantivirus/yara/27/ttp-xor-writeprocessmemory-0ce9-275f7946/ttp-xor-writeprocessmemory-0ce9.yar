rule TTP_XOR_WriteProcessMemory_0ce9 {
  strings:
    $key_0ce9 = { 5b 9b [2] 69 b9 [2] 6f 8c [2] 41 8c [2] 7e 90 }

  condition:
    any of them
}