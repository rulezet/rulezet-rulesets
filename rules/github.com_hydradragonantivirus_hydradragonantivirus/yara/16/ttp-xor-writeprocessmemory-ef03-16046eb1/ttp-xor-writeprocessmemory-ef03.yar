rule TTP_XOR_WriteProcessMemory_ef03 {
  strings:
    $key_ef03 = { b8 71 [2] 8a 53 [2] 8c 66 [2] a2 66 [2] 9d 7a }

  condition:
    any of them
}