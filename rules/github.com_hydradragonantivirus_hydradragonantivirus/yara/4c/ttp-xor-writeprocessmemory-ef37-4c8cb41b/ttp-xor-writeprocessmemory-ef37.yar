rule TTP_XOR_WriteProcessMemory_ef37 {
  strings:
    $key_ef37 = { b8 45 [2] 8a 67 [2] 8c 52 [2] a2 52 [2] 9d 4e }

  condition:
    any of them
}