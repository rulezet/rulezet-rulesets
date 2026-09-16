rule TTP_XOR_WriteProcessMemory_a935 {
  strings:
    $key_a935 = { fe 47 [2] cc 65 [2] ca 50 [2] e4 50 [2] db 4c }

  condition:
    any of them
}