rule TTP_XOR_WriteProcessMemory_0c09 {
  strings:
    $key_0c09 = { 5b 7b [2] 69 59 [2] 6f 6c [2] 41 6c [2] 7e 70 }

  condition:
    any of them
}