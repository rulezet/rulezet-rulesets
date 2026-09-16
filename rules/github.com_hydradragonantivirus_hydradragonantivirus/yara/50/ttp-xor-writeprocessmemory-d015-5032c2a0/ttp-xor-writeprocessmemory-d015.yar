rule TTP_XOR_WriteProcessMemory_d015 {
  strings:
    $key_d015 = { 87 67 [2] b5 45 [2] b3 70 [2] 9d 70 [2] a2 6c }

  condition:
    any of them
}