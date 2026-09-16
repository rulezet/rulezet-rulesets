rule TTP_XOR_WriteProcessMemory_216e {
  strings:
    $key_216e = { 76 1c [2] 44 3e [2] 42 0b [2] 6c 0b [2] 53 17 }

  condition:
    any of them
}