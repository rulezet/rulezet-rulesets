rule TTP_XOR_WriteProcessMemory_a43c {
  strings:
    $key_a43c = { f3 4e [2] c1 6c [2] c7 59 [2] e9 59 [2] d6 45 }

  condition:
    any of them
}