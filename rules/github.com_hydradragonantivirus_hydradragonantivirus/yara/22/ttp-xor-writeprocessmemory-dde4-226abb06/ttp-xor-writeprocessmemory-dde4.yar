rule TTP_XOR_WriteProcessMemory_dde4 {
  strings:
    $key_dde4 = { 8a 96 [2] b8 b4 [2] be 81 [2] 90 81 [2] af 9d }

  condition:
    any of them
}