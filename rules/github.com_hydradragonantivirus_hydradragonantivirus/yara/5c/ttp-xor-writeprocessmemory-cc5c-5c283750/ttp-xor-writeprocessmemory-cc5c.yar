rule TTP_XOR_WriteProcessMemory_cc5c {
  strings:
    $key_cc5c = { 9b 2e [2] a9 0c [2] af 39 [2] 81 39 [2] be 25 }

  condition:
    any of them
}