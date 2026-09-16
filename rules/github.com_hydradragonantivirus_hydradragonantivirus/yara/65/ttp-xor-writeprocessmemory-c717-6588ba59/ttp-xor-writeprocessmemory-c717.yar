rule TTP_XOR_WriteProcessMemory_c717 {
  strings:
    $key_c717 = { 90 65 [2] a2 47 [2] a4 72 [2] 8a 72 [2] b5 6e }

  condition:
    any of them
}