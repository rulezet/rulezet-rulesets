rule TTP_XOR_WriteProcessMemory_e269 {
  strings:
    $key_e269 = { b5 1b [2] 87 39 [2] 81 0c [2] af 0c [2] 90 10 }

  condition:
    any of them
}