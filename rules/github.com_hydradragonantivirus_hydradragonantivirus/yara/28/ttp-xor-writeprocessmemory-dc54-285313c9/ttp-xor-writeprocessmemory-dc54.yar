rule TTP_XOR_WriteProcessMemory_dc54 {
  strings:
    $key_dc54 = { 8b 26 [2] b9 04 [2] bf 31 [2] 91 31 [2] ae 2d }

  condition:
    any of them
}