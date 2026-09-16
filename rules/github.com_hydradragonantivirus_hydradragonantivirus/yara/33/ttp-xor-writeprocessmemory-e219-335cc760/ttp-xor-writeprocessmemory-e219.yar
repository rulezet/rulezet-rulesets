rule TTP_XOR_WriteProcessMemory_e219 {
  strings:
    $key_e219 = { b5 6b [2] 87 49 [2] 81 7c [2] af 7c [2] 90 60 }

  condition:
    any of them
}