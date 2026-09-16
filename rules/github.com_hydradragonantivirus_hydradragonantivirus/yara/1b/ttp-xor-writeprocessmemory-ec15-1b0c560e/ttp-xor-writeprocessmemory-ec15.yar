rule TTP_XOR_WriteProcessMemory_ec15 {
  strings:
    $key_ec15 = { bb 67 [2] 89 45 [2] 8f 70 [2] a1 70 [2] 9e 6c }

  condition:
    any of them
}