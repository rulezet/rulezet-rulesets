rule TTP_XOR_WriteProcessMemory_dc22 {
  strings:
    $key_dc22 = { 8b 50 [2] b9 72 [2] bf 47 [2] 91 47 [2] ae 5b }

  condition:
    any of them
}