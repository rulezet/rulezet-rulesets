rule TTP_XOR_WriteProcessMemory_0f11 {
  strings:
    $key_0f11 = { 58 63 [2] 6a 41 [2] 6c 74 [2] 42 74 [2] 7d 68 }

  condition:
    any of them
}