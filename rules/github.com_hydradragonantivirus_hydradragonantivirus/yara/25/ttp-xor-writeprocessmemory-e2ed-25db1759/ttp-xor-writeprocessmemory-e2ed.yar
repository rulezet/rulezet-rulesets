rule TTP_XOR_WriteProcessMemory_e2ed {
  strings:
    $key_e2ed = { b5 9f [2] 87 bd [2] 81 88 [2] af 88 [2] 90 94 }

  condition:
    any of them
}