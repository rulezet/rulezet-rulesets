rule TTP_XOR_WriteProcessMemory_4239 {
  strings:
    $key_4239 = { 15 4b [2] 27 69 [2] 21 5c [2] 0f 5c [2] 30 40 }

  condition:
    any of them
}