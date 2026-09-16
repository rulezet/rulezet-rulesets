rule TTP_XOR_WriteProcessMemory_cc29 {
  strings:
    $key_cc29 = { 9b 5b [2] a9 79 [2] af 4c [2] 81 4c [2] be 50 }

  condition:
    any of them
}