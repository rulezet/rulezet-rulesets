rule TTP_XOR_WriteProcessMemory_da09 {
  strings:
    $key_da09 = { 8d 7b [2] bf 59 [2] b9 6c [2] 97 6c [2] a8 70 }

  condition:
    any of them
}