rule TTP_XOR_WriteProcessMemory_c631 {
  strings:
    $key_c631 = { 91 43 [2] a3 61 [2] a5 54 [2] 8b 54 [2] b4 48 }

  condition:
    any of them
}