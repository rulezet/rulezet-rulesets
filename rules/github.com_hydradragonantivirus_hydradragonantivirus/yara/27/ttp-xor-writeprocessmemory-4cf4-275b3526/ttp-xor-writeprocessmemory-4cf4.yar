rule TTP_XOR_WriteProcessMemory_4cf4 {
  strings:
    $key_4cf4 = { 1b 86 [2] 29 a4 [2] 2f 91 [2] 01 91 [2] 3e 8d }

  condition:
    any of them
}