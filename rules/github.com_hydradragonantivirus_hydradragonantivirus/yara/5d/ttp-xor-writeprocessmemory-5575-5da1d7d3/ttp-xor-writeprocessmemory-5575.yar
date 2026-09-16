rule TTP_XOR_WriteProcessMemory_5575 {
  strings:
    $key_5575 = { 02 07 [2] 30 25 [2] 36 10 [2] 18 10 [2] 27 0c }

  condition:
    any of them
}