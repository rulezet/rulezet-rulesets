rule TTP_XOR_WriteProcessMemory_c639 {
  strings:
    $key_c639 = { 91 4b [2] a3 69 [2] a5 5c [2] 8b 5c [2] b4 40 }

  condition:
    any of them
}