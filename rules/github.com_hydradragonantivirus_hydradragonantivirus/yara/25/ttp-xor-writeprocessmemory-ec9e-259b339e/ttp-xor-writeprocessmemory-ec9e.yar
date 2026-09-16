rule TTP_XOR_WriteProcessMemory_ec9e {
  strings:
    $key_ec9e = { bb ec [2] 89 ce [2] 8f fb [2] a1 fb [2] 9e e7 }

  condition:
    any of them
}