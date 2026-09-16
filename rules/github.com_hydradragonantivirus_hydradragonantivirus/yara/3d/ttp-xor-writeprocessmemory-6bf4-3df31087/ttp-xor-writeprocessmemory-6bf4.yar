rule TTP_XOR_WriteProcessMemory_6bf4 {
  strings:
    $key_6bf4 = { 3c 86 [2] 0e a4 [2] 08 91 [2] 26 91 [2] 19 8d }

  condition:
    any of them
}