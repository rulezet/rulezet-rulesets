rule TTP_XOR_WriteProcessMemory_2839 {
  strings:
    $key_2839 = { 7f 4b [2] 4d 69 [2] 4b 5c [2] 65 5c [2] 5a 40 }

  condition:
    any of them
}