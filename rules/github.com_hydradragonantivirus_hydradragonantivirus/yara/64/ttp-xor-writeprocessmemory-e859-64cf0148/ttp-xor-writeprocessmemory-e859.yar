rule TTP_XOR_WriteProcessMemory_e859 {
  strings:
    $key_e859 = { bf 2b [2] 8d 09 [2] 8b 3c [2] a5 3c [2] 9a 20 }

  condition:
    any of them
}