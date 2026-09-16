rule TTP_XOR_WriteProcessMemory_ef13 {
  strings:
    $key_ef13 = { b8 61 [2] 8a 43 [2] 8c 76 [2] a2 76 [2] 9d 6a }

  condition:
    any of them
}