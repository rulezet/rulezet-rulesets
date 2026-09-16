rule TTP_XOR_WriteProcessMemory_ed09 {
  strings:
    $key_ed09 = { ba 7b [2] 88 59 [2] 8e 6c [2] a0 6c [2] 9f 70 }

  condition:
    any of them
}