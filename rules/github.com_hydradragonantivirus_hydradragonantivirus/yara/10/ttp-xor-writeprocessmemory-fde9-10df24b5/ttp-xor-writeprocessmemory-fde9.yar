rule TTP_XOR_WriteProcessMemory_fde9 {
  strings:
    $key_fde9 = { aa 9b [2] 98 b9 [2] 9e 8c [2] b0 8c [2] 8f 90 }

  condition:
    any of them
}