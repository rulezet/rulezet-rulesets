rule TTP_XOR_WriteProcessMemory_d056 {
  strings:
    $key_d056 = { 87 24 [2] b5 06 [2] b3 33 [2] 9d 33 [2] a2 2f }

  condition:
    any of them
}