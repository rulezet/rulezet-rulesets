rule TTP_XOR_WriteProcessMemory_0635 {
  strings:
    $key_0635 = { 51 47 [2] 63 65 [2] 65 50 [2] 4b 50 [2] 74 4c }

  condition:
    any of them
}