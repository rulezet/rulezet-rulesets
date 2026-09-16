rule TTP_XOR_WriteProcessMemory_0c33 {
  strings:
    $key_0c33 = { 5b 41 [2] 69 63 [2] 6f 56 [2] 41 56 [2] 7e 4a }

  condition:
    any of them
}