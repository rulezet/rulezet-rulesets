rule TTP_XOR_WriteProcessMemory_ddf4 {
  strings:
    $key_ddf4 = { 8a 86 [2] b8 a4 [2] be 91 [2] 90 91 [2] af 8d }

  condition:
    any of them
}