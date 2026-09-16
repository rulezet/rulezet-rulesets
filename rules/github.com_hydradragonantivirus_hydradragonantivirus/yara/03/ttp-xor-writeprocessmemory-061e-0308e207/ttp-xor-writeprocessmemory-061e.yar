rule TTP_XOR_WriteProcessMemory_061e {
  strings:
    $key_061e = { 51 6c [2] 63 4e [2] 65 7b [2] 4b 7b [2] 74 67 }

  condition:
    any of them
}