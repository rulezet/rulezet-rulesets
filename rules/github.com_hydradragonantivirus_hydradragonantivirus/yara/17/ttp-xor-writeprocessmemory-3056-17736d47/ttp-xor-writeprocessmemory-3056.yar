rule TTP_XOR_WriteProcessMemory_3056 {
  strings:
    $key_3056 = { 67 24 [2] 55 06 [2] 53 33 [2] 7d 33 [2] 42 2f }

  condition:
    any of them
}