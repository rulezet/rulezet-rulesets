rule TTP_XOR_WriteProcessMemory_0659 {
  strings:
    $key_0659 = { 51 2b [2] 63 09 [2] 65 3c [2] 4b 3c [2] 74 20 }

  condition:
    any of them
}