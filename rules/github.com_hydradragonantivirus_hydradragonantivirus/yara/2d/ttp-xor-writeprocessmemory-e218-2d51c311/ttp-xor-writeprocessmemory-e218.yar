rule TTP_XOR_WriteProcessMemory_e218 {
  strings:
    $key_e218 = { b5 6a [2] 87 48 [2] 81 7d [2] af 7d [2] 90 61 }

  condition:
    any of them
}