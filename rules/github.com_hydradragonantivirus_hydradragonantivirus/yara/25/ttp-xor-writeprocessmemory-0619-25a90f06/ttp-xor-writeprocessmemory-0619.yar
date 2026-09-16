rule TTP_XOR_WriteProcessMemory_0619 {
  strings:
    $key_0619 = { 51 6b [2] 63 49 [2] 65 7c [2] 4b 7c [2] 74 60 }

  condition:
    any of them
}