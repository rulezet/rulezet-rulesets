rule TTP_XOR_WriteProcessMemory_4cf5 {
  strings:
    $key_4cf5 = { 1b 87 [2] 29 a5 [2] 2f 90 [2] 01 90 [2] 3e 8c }

  condition:
    any of them
}