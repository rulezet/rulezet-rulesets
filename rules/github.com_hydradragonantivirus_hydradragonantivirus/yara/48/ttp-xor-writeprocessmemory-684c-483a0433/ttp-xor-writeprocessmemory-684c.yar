rule TTP_XOR_WriteProcessMemory_684c {
  strings:
    $key_684c = { 3f 3e [2] 0d 1c [2] 0b 29 [2] 25 29 [2] 1a 35 }

  condition:
    any of them
}