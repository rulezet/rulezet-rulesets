rule TTP_XOR_WriteProcessMemory_fee3 {
  strings:
    $key_fee3 = { a9 91 [2] 9b b3 [2] 9d 86 [2] b3 86 [2] 8c 9a }

  condition:
    any of them
}