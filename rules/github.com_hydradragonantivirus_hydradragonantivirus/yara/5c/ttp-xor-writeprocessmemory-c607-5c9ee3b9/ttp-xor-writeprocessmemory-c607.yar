rule TTP_XOR_WriteProcessMemory_c607 {
  strings:
    $key_c607 = { 91 75 [2] a3 57 [2] a5 62 [2] 8b 62 [2] b4 7e }

  condition:
    any of them
}