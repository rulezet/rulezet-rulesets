rule TTP_XOR_WriteProcessMemory_dc19 {
  strings:
    $key_dc19 = { 8b 6b [2] b9 49 [2] bf 7c [2] 91 7c [2] ae 60 }

  condition:
    any of them
}