rule TTP_XOR_WriteProcessMemory_683b {
  strings:
    $key_683b = { 3f 49 [2] 0d 6b [2] 0b 5e [2] 25 5e [2] 1a 42 }

  condition:
    any of them
}