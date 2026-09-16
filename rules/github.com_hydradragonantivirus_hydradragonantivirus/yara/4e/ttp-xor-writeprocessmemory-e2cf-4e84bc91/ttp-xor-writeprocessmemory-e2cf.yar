rule TTP_XOR_WriteProcessMemory_e2cf {
  strings:
    $key_e2cf = { b5 bd [2] 87 9f [2] 81 aa [2] af aa [2] 90 b6 }

  condition:
    any of them
}