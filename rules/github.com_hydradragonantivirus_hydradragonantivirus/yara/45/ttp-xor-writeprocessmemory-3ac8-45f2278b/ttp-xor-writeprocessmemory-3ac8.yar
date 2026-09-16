rule TTP_XOR_WriteProcessMemory_3ac8 {
  strings:
    $key_3ac8 = { 6d ba [2] 5f 98 [2] 59 ad [2] 77 ad [2] 48 b1 }

  condition:
    any of them
}