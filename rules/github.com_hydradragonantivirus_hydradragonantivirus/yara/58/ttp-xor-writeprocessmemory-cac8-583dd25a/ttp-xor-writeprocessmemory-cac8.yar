rule TTP_XOR_WriteProcessMemory_cac8 {
  strings:
    $key_cac8 = { 9d ba [2] af 98 [2] a9 ad [2] 87 ad [2] b8 b1 }

  condition:
    any of them
}