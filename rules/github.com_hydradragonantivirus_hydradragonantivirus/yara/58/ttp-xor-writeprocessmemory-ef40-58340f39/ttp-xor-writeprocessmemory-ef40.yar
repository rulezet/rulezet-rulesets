rule TTP_XOR_WriteProcessMemory_ef40 {
  strings:
    $key_ef40 = { b8 32 [2] 8a 10 [2] 8c 25 [2] a2 25 [2] 9d 39 }

  condition:
    any of them
}