rule TTP_XOR_WriteProcessMemory_c039 {
  strings:
    $key_c039 = { 97 4b [2] a5 69 [2] a3 5c [2] 8d 5c [2] b2 40 }

  condition:
    any of them
}