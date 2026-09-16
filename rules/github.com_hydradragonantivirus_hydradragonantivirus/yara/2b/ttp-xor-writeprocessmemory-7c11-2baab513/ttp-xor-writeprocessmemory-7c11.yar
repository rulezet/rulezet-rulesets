rule TTP_XOR_WriteProcessMemory_7c11 {
  strings:
    $key_7c11 = { 2b 63 [2] 19 41 [2] 1f 74 [2] 31 74 [2] 0e 68 }

  condition:
    any of them
}