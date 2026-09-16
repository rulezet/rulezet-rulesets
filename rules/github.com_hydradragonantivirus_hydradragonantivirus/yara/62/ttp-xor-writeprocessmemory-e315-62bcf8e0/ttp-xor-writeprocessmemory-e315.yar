rule TTP_XOR_WriteProcessMemory_e315 {
  strings:
    $key_e315 = { b4 67 [2] 86 45 [2] 80 70 [2] ae 70 [2] 91 6c }

  condition:
    any of them
}