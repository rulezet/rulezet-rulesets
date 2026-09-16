rule TTP_XOR_WriteProcessMemory_043d {
  strings:
    $key_043d = { 53 4f [2] 61 6d [2] 67 58 [2] 49 58 [2] 76 44 }

  condition:
    any of them
}