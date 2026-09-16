rule TTP_XOR_WriteProcessMemory_eb75 {
  strings:
    $key_eb75 = { bc 07 [2] 8e 25 [2] 88 10 [2] a6 10 [2] 99 0c }

  condition:
    any of them
}