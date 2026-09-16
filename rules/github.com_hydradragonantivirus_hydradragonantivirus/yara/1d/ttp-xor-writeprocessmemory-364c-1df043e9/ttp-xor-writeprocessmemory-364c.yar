rule TTP_XOR_WriteProcessMemory_364c {
  strings:
    $key_364c = { 61 3e [2] 53 1c [2] 55 29 [2] 7b 29 [2] 44 35 }

  condition:
    any of them
}