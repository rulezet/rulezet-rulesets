rule TTP_XOR_WriteProcessMemory_696e {
  strings:
    $key_696e = { 3e 1c [2] 0c 3e [2] 0a 0b [2] 24 0b [2] 1b 17 }

  condition:
    any of them
}