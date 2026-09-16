rule TTP_XOR_WriteProcessMemory_7629 {
  strings:
    $key_7629 = { 21 5b [2] 13 79 [2] 15 4c [2] 3b 4c [2] 04 50 }

  condition:
    any of them
}