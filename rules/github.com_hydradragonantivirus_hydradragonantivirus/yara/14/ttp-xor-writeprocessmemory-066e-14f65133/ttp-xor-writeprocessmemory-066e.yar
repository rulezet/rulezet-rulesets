rule TTP_XOR_WriteProcessMemory_066e {
  strings:
    $key_066e = { 51 1c [2] 63 3e [2] 65 0b [2] 4b 0b [2] 74 17 }

  condition:
    any of them
}