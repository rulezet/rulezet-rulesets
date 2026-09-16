rule TTP_XOR_WriteProcessMemory_fee9 {
  strings:
    $key_fee9 = { a9 9b [2] 9b b9 [2] 9d 8c [2] b3 8c [2] 8c 90 }

  condition:
    any of them
}