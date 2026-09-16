rule TTP_XOR_WriteProcessMemory_dd6f {
  strings:
    $key_dd6f = { 8a 1d [2] b8 3f [2] be 0a [2] 90 0a [2] af 16 }

  condition:
    any of them
}