rule TTP_XOR_WriteProcessMemory_045c {
  strings:
    $key_045c = { 53 2e [2] 61 0c [2] 67 39 [2] 49 39 [2] 76 25 }

  condition:
    any of them
}