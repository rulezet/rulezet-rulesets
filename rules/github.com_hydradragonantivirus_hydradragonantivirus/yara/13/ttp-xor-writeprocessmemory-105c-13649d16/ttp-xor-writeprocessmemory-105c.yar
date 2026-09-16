rule TTP_XOR_WriteProcessMemory_105c {
  strings:
    $key_105c = { 47 2e [2] 75 0c [2] 73 39 [2] 5d 39 [2] 62 25 }

  condition:
    any of them
}