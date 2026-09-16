rule TTP_XOR_WriteProcessMemory_c620 {
  strings:
    $key_c620 = { 91 52 [2] a3 70 [2] a5 45 [2] 8b 45 [2] b4 59 }

  condition:
    any of them
}