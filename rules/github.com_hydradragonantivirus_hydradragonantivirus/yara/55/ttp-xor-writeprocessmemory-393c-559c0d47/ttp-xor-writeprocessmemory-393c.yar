rule TTP_XOR_WriteProcessMemory_393c {
  strings:
    $key_393c = { 6e 4e [2] 5c 6c [2] 5a 59 [2] 74 59 [2] 4b 45 }

  condition:
    any of them
}