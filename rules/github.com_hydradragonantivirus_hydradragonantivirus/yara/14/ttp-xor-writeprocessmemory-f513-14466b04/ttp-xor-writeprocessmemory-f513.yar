rule TTP_XOR_WriteProcessMemory_f513 {
  strings:
    $key_f513 = { a2 61 [2] 90 43 [2] 96 76 [2] b8 76 [2] 87 6a }

  condition:
    any of them
}