rule TTP_XOR_WriteProcessMemory_287e {
  strings:
    $key_287e = { 7f 0c [2] 4d 2e [2] 4b 1b [2] 65 1b [2] 5a 07 }

  condition:
    any of them
}