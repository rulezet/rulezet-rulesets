rule TTP_XOR_WriteProcessMemory_0804 {
  strings:
    $key_0804 = { 5f 76 [2] 6d 54 [2] 6b 61 [2] 45 61 [2] 7a 7d }

  condition:
    any of them
}