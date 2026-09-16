rule TTP_XOR_WriteProcessMemory_dbec {
  strings:
    $key_dbec = { 8c 9e [2] be bc [2] b8 89 [2] 96 89 [2] a9 95 }

  condition:
    any of them
}