rule TTP_XOR_WriteProcessMemory_0c11 {
  strings:
    $key_0c11 = { 5b 63 [2] 69 41 [2] 6f 74 [2] 41 74 [2] 7e 68 }

  condition:
    any of them
}