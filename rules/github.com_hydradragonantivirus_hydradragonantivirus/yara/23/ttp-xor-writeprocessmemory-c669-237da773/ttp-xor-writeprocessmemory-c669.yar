rule TTP_XOR_WriteProcessMemory_c669 {
  strings:
    $key_c669 = { 91 1b [2] a3 39 [2] a5 0c [2] 8b 0c [2] b4 10 }

  condition:
    any of them
}