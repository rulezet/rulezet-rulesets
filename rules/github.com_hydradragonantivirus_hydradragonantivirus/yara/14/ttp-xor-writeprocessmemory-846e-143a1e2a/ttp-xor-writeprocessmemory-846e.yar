rule TTP_XOR_WriteProcessMemory_846e {
  strings:
    $key_846e = { d3 1c [2] e1 3e [2] e7 0b [2] c9 0b [2] f6 17 }

  condition:
    any of them
}