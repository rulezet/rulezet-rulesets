rule TTP_XOR_WriteProcessMemory_dcec {
  strings:
    $key_dcec = { 8b 9e [2] b9 bc [2] bf 89 [2] 91 89 [2] ae 95 }

  condition:
    any of them
}