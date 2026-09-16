rule TTP_XOR_WriteProcessMemory_062c {
  strings:
    $key_062c = { 51 5e [2] 63 7c [2] 65 49 [2] 4b 49 [2] 74 55 }

  condition:
    any of them
}