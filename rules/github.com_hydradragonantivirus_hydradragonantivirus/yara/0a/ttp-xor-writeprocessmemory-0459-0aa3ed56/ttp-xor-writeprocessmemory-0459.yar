rule TTP_XOR_WriteProcessMemory_0459 {
  strings:
    $key_0459 = { 53 2b [2] 61 09 [2] 67 3c [2] 49 3c [2] 76 20 }

  condition:
    any of them
}