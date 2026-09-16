rule TTP_XOR_WriteProcessMemory_282b {
  strings:
    $key_282b = { 7f 59 [2] 4d 7b [2] 4b 4e [2] 65 4e [2] 5a 52 }

  condition:
    any of them
}