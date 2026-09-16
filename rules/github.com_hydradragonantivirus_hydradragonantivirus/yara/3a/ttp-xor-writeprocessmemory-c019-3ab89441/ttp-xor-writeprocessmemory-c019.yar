rule TTP_XOR_WriteProcessMemory_c019 {
  strings:
    $key_c019 = { 97 6b [2] a5 49 [2] a3 7c [2] 8d 7c [2] b2 60 }

  condition:
    any of them
}