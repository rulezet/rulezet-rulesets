rule TTP_XOR_WriteProcessMemory_033c {
  strings:
    $key_033c = { 54 4e [2] 66 6c [2] 60 59 [2] 4e 59 [2] 71 45 }

  condition:
    any of them
}