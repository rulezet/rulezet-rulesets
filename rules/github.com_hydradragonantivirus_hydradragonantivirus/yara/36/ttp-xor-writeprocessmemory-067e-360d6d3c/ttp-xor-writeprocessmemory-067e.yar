rule TTP_XOR_WriteProcessMemory_067e {
  strings:
    $key_067e = { 51 0c [2] 63 2e [2] 65 1b [2] 4b 1b [2] 74 07 }

  condition:
    any of them
}