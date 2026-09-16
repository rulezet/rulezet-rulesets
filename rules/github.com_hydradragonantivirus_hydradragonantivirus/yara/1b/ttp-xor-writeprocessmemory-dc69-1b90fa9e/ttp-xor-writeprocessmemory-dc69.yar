rule TTP_XOR_WriteProcessMemory_dc69 {
  strings:
    $key_dc69 = { 8b 1b [2] b9 39 [2] bf 0c [2] 91 0c [2] ae 10 }

  condition:
    any of them
}