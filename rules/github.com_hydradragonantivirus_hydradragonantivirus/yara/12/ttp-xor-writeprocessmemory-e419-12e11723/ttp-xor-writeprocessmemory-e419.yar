rule TTP_XOR_WriteProcessMemory_e419 {
  strings:
    $key_e419 = { b3 6b [2] 81 49 [2] 87 7c [2] a9 7c [2] 96 60 }

  condition:
    any of them
}