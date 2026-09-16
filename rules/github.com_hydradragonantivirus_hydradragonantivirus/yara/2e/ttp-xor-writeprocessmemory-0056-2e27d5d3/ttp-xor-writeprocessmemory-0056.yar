rule TTP_XOR_WriteProcessMemory_0056 {
  strings:
    $key_0056 = { 57 24 [2] 65 06 [2] 63 33 [2] 4d 33 [2] 72 2f }

  condition:
    any of them
}