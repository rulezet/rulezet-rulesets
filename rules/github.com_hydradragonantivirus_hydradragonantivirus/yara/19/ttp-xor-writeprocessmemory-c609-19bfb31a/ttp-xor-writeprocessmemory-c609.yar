rule TTP_XOR_WriteProcessMemory_c609 {
  strings:
    $key_c609 = { 91 7b [2] a3 59 [2] a5 6c [2] 8b 6c [2] b4 70 }

  condition:
    any of them
}